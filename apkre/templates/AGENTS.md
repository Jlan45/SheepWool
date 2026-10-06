# APK Static Analysis — Task Specification

You are performing an authorized static security review of a single Android
application. Work autonomously from the evidence in this directory. Nobody will
answer questions mid-run; when you cannot determine something, record it under
`unknowns` and move on.

| | |
|---|---|
| **Target** | `{{APK_NAME}}` |
| **SHA-256** | `{{APK_SHA256}}` |
| **Size** | {{APK_SIZE}} bytes |
| **Location** | `./{{APK_NAME}}` (this directory is the workspace root) |

---

## 1. Tooling

You have two analysis engines. Use both — they fail in different places, and
the gaps are where interesting findings live.

### jadx (MCP server `jadx`)

A headless JADX decompiler, preloaded with this APK. Decompiled Java/Kotlin,
decoded `AndroidManifest.xml`, resources, smali, and cross-references. This is
your primary tool for application logic.

Call `index_status` first. JADX indexes lazily under a time budget and may
report `ready: false` while still building — the returned `decompiled_classes`
and `total_classes` tell you what is available *now*. Use what is there, and
call `index_status` again later to see whether more arrived. Do not block
waiting for `coverage_complete`.

Most useful tools: `get_android_manifest`, `get_main_activity_class`,
`get_all_classes`, `get_package_tree`, `get_class_source`,
`get_class_sources` (batch), `search_classes_by_keyword`,
`search_method_by_name`, `get_method_by_name`, `get_methods_of_class`,
`get_fields_of_class`, `get_xrefs_to_class`, `get_xrefs_to_method`,
`get_xrefs_to_field`, `get_xrefs_from_class`, `get_call_graph`,
`get_subclasses`, `get_smali_of_class`, `get_strings`, `get_resource_file`,
`get_all_resource_file_names`, `search_string_constants`,
`find_string_usages`, `current_apk`.

If the server has not loaded a file, call `load_apk` with the absolute path of
`./{{APK_NAME}}`.

### rizin (Skill: `rizin-re`)

Read the `rizin-re` skill before using it. It is the low-level complement to
jadx: raw Dalvik structure, string mining, and native `.so` hardening audits.
Reach for it whenever jadx is blind — undecodable methods, obfuscation,
`DexClassLoader`, or anything native.

Both `rizin` and `rz-bin` are on `PATH` and take `-j` for JSON output.

---

## 2. Workflow

Follow this order. Each phase feeds the next; do not skip ahead and guess.

### Phase 1 — Identity and surface

1. `get_android_manifest` — read the whole thing.
2. `get_main_activity_class` and `get_main_application_classes_names`.
3. `get_all_classes` / `get_package_tree` for the class inventory.

Establish: package name, version, SDK levels, the launcher activity, the full
component list, and which declared permissions are actually justified by the
code you will see later.

### Phase 2 — Capabilities and dependencies

1. `third_party_sdks` — walk the top-level package namespaces. Note analytics,
   ad, attribution, push, payments, and crash SDKs separately; they carry
   privacy weight.
2. Locate the `Application` subclass and any content providers. Providers
   declared early in the manifest are often initialised before `Application`
   and are a common source of uninitialised-state bugs.
3. Identify the app's actual job (terminal, banking, launcher, IoT controller…)
   from its entry points and UI code.

### Phase 3 — Attack surface (highest value)

This is the part that matters. Work through it deliberately:

1. **Exported components.** For every `activity`, `service`, `receiver` and
   `provider` in the manifest, determine `android:exported`, any
   `android:permission` guard, and the intent filters. A component exported
   without a permission is reachable by any app on the device.
2. **Deep-link handlers.** Read the data-path handling code with
   `get_class_source` / `get_xrefs_to_method` for each deep link. Ask: is the
   input validated, is the target resolved safely, can it be pointed at a
   `file://` or `content://` URI?
3. **Providers.** `content://` URIs with `grantUriPermissions`, path-permission
   patterns, and SQL built by string concatenation. Use
   `get_xrefs_to_method` on the query/insert/delete paths and read the actual
   `rawQuery` / `execSQL` calls.
4. **WebView.** `shouldOverrideUrlLoading`, `addJavascriptInterface`,
   `setJavaScriptEnabled`, `onReceivedSslError`. A JS bridge reachable from
   remote content is a full compromise path.
5. **IPC and pending intents.** `PendingIntent` with `FLAG_MUTABLE`, implicit
   intents, unvalidated `Intent` extras read back by another component.

For each real finding, use cross-references to confirm reachability before you
report it. A sink without a caller is a note, not a vulnerability.

### Phase 4 — Secrets, network, crypto

1. `search_string_constants` for URLs, hosts, API keys, tokens, JWTs, private
   key headers, and Firebase config. Cross-check with
   `find_string_usages` to locate each in code.
2. Use the `rizin-re` skill to dump the DEX string pool (`rz-bin -qq -zz`) — it
   catches constants jadx's index does not surface.
3. Cleartext HTTP: `usesCleartextTraffic`, `networkSecurityConfig`, and any
   trust-all `TrustManager` / `HostnameVerifier` / `onReceivedSslError`.
4. Crypto: find `Cipher.getInstance`, `MessageDigest`, `SecretKeySpec`, and
   flag ECB mode, MD5/SHA-1 for integrity, static IVs, and hardcoded keys.

**Never write a full live secret into your output.** Report the kind, the
containing class or method, and a masked prefix.

### Phase 5 — Anti-analysis and native code

1. Root / emulator / debugger / tamper detection — string and API evidence.
2. Obfuscation and packing: ProGuard/R8 renaming, string encryption, a
   `DexClassLoader` bootstrap, or a `lib/*/libjiagu.so`-style packer.
3. Native libraries: for every `.so`, run `rz-bin -I -j` and record
   `canary`, `nx`, `pie`, `relro`, `stripped`. Missing canary or NX on a
   library handling untrusted input is a genuine, reportable weakness.
4. Certificate: `keytool -printcert -file` on the `META-INF` certificate to
   identify the signer and spot a debug/self-signed key.

### Phase 6 — Synthesise

Score the app. `risk_score` is 0–100 and must be justified by the findings you
actually observed, not by the app's category. A flashlight app with one ad SDK
is not automatically a 70. Anchor the score to the highest-severity concrete
finding, and set `confidence` honestly — `low` if decompilation was largely
incomplete or the app is heavily packed.

---

## 3. Evidence rules

- **Every claim needs a source.** Name the class, the method, or the exact
  command that produced it.
- **Never invent** a class name, URL, key, package, or CVE. If you did not see
  it, it does not go in the report.
- **Separate observation from inference.** "Calls
  `Cipher.getInstance("AES/ECB/PKCS5Padding")`" is an observation. "Likely
  encrypts the licence locally" is an inference — label it as such.
- **Verify reachability.** Use xrefs before calling a sink exploitable.
- **Prefer depth over breadth.** Three confirmed findings beat thirty guesses.
- **Be honest about limits.** Incomplete decompilation, a truncated index, an
  unresolvable packer, or a missing tool all belong in `unknowns`.

---

## 4. Output contract

Finish by emitting **one JSON object** matching the supplied schema. The reply
must be that object and nothing else.

- First character `{`, last character `}`.
- No markdown code fences, no preamble, no trailing commentary.
- Every field required by the schema must be present. Use empty arrays rather
  than omitting a key.
- `secrets[].redacted_value` is masked, never the full credential.
- `unknowns` is mandatory and must be honest — an empty list on a large
  obfuscated app is a red flag about the report, not a sign of perfection.

## 5. Suggested dynamic follow-up

`dynamic_analysis_plan` should list concrete next steps an analyst could run
with a device: Frida hook points, functions to intercept, traffic-capture
targets, and behaviours worth confirming at runtime. Make them specific to this
app's classes — `"hook OkHttpClient$RealCall#connect"` beats `"check network
security"`.
