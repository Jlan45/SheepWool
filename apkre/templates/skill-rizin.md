---
name: rizin-re
description: Reverse-engineer Android DEX bytecode and native ARM/ELF libraries with rizin and rz-bin. Use when inspecting classes.dex structure, enumerating classes and methods, extracting strings, finding hardcoded URLs or keys, checking native library hardening (canary, NX, PIE, RELRO), or when jadx decompilation is incomplete or a class fails to decompile.
---

# rizin for Android RE

`rizin` (and its `rz-bin` front-end) is the low-level tool here. jadx handles
Java decompilation; **rizin is what you reach for when jadx is blind** — packed
or obfuscated DEX, dynamically loaded code, native libraries, and raw string
mining. Treat it as the second opinion on anything jadx cannot explain.

Both binaries are already on `PATH` (`rizin`, `rz-bin`, plus `rz-hash`, `rz-asm`,
`rz-find`, `rz-diff`, `rz-run`, `rz-sign`, `rz-ax`).

## Golden rule: always pass `-j`

`rz-bin` defaults to a colourised columnar table that is miserable to parse.
Append `-j` for machine-readable JSON. Always quote commands so the agent's own
parser is not your only reader.

```bash
rz-bin -I -j app/lib/arm64-v8a/libnative.so   # binary info as JSON
rz-bin -c -j app/classes.dex                  # every class + methods + fields
```

## Extract before you analyse

Never point rizin at the APK. Unpack first and work on real files:

```bash
mkdir -p work && cd work
unzip -o -q ../target.apk 'classes*.dex' 'lib/*' 'assets/*' 'AndroidManifest.xml'
ls -la
```

## DEX (`classes*.dex`)

rz-bin ships a Dalvik plugin, so DEX is a first-class citizen — no conversion.

| Goal | Command |
|---|---|
| Format / SDK target | `rz-bin -I -j classes.dex` → `arch: dalvik`, `class: Android 7 (API level 24 and earlier)` |
| **Every class, method and field** | `rz-bin -c -j classes.dex` |
| Entry points | `rz-bin -e -j classes.dex` |
| Imports (framework calls made) | `rz-bin -i -j classes.dex` |
| Symbols | `rz-bin -s -j classes.dex` |
| All strings | `rz-bin -qq -zz classes.dex` |

The `-I` output names the **DEX API level** the file targets. A mismatch between
that and the manifest's `targetSdkVersion` is a real finding — it is how loaded
code behaves differently from declared code.

`rz-bin -c -j` returns, per class: `classname`, `visibility`, `super`, `methods`
(each with `name`, `flags`, `addr`) and `fields`. That is enough to compute class
counts, spot `$$ServiceLoaderMethods`-style artefacts, and identify
`DexClassLoader` / `InMemoryDexClassLoader` call sites.

### Class-name heuristics worth running

```bash
# Top-level namespaces, sorted by class count - separates first-party from SDK bulk
rz-bin -c -j classes.dex \
  | python3 -c "import json,sys,collections; \
      c=json.load(sys.stdin)['classes']; \
      k=collections.Counter('.'.join(x['classname'].split('.')[:2]) for x in c); \
      [print(f'{v:6} {n}') for n,v in k.most_common(40)]"

# Single-letter / obfuscated classes: a strong packing signal
rz-bin -c -j classes.dex \
  | python3 -c "import json,sys; \
      c=json.load(sys.stdin)['classes']; \
      o=[x['classname'] for x in c if len(x['classname'].split('.')[-1])<=2]; \
      print(f'{len(o)}/{len(c)} short-named'); print('\n'.join(o[:40]))"
```

## Native libraries (`lib/<abi>/*.so`)

### Hardening audit — run this on every `.so`

```bash
for so in $(find lib -name '*.so'); do
  echo "== $so"
  rz-bin -I -j "$so" \
    | python3 -c "import json,sys; i=json.load(sys.stdin)['info']; \
        print('  arch',i.get('arch'),i.get('bits'),'| stripped',i.get('stripped'),\
              '| canary',i.get('canary'),'| nx',i.get('nx'),'| pie',i.get('pie'),\
              '| relro',i.get('relro'),'| static',i.get('static'))"
done
```

Interpret it honestly:

- `canary: false` — stack buffer overflows are **exploitable**. High severity.
- `nx: false` — the stack is executable; classic shellcode target.
- `pie: false` with a non-PIE ELF — no ASLR for the library.
- `relro` other than `full` — GOT is writable at runtime.
- `stripped: true` — no symbols, so your symbol-based reasoning is a guess.
  Confirm with a string or an import before claiming a function's purpose.
- `static: true` — a static library carries its own libc copy; flag
  duplicate-symbol and outdated-toolchain risk.

### Deep analysis when a library matters

```bash
rizin -q -e scr.color=0 -c 'aaa; afl' lib/arm64-v8a/libnative.so   # functions
rizin -q -e scr.color=0 -c 'aaa; iz~http' lib/arm64-v8a/libnative.so # strings
rizin -q -e scr.color=0 -c 'aaa; axt @ sym.imp.strlen' lib/.../libnative.so
rizin -q -e scr.color=0 -c 'iS' lib/.../libnative.so               # sections
rizin -q -e scr.color=0 -c 'ii' lib/.../libnative.so               # imports
```

`aaa` is slow. On a large `.so` use `-A` only when you need cross-references,
and prefer `af @ entry0` to start narrow.

## String mining across the whole APK

DEX string pools are the single richest source. This is where URLs, keys and
detection logic actually live:

```bash
rz-bin -qq -zz classes.dex > strings.txt

grep -iEo 'https?://[^ "'"'"'<>)]+' strings.txt | sort -u
grep -nE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|xox[baprs]-|eyJ[A-Za-z0-9_-]{10,}\.' strings.txt
grep -nEi 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' strings.txt
grep -nEi '/(system/(x?bin|app)/su|su$)|magisk|supersu|test-keys' strings.txt
grep -nEi 'TracerPid|ptrace|isDebuggerConnected' strings.txt
grep -nEi 'goldfish|generic|sdk_gphone|ro\.hardware' strings.txt
grep -nEi 'DES|ECB|MD5|SHA-1|TrustManager|X509TrustManager' strings.txt
```

Always **redact** what you find. Report the kind, the location and a masked
prefix. Never write a full live credential into a report.

## When to prefer rizin over jadx

| Situation | Use |
|---|---|
| Normal Java/Kotlin app logic | jadx MCP — readable, cross-referenced |
| `jadx` throws / method shows `throw new UnsupportedOperationException("Method not decompiled")` | rizin `get_smali_of_class`, then reason in smali |
| Obfuscated or packed APK | rizin DEX class list + string dump |
| Native `.so` with interesting strings | rizin, always |
| Dynamic class loading | rizin: find the `DexClassLoader` call, then the asset it reads |
| Signature/certificate checks | `META-INF/*.RSA` → `keytool -printcert -file <cert>` |

## Reporting rules

- Cite the exact command that produced each claim. If you did not run it, you
  do not know it.
- Distinguish *observed* from *inferred*. "Imports `javax.crypto.spec.SecretKeySpec`
  with `AES/ECB/PKCS5Padding`" is observed. "Probably encrypts the licence" is
  inferred — say so.
- A hardening flag read straight from `rz-bin -I -j` is a fact. An opinion about
  exploitability is an inference. Keep them separate.
- If a tool is missing or errors, say so in `unknowns` rather than guessing.
