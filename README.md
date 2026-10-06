# apkre

Batch Android APK static analysis driven by the **mcode** CLI.

Point it at a directory of APKs. For each one it builds a self-contained
workspace, launches a single one-shot `mcode exec` inside it, and gets back a
schema-validated JSON finding set. No manual decompilation, no per-APK babysitting.

```
apkre run ~/apks -c 8
```

---

## How it works

Each APK gets its own workspace holding **only** what the agent needs:

```
<out>/workspaces/files-2fe900bf43d7/
├── .agents/
│   └── rizin-re/
│       └── SKILL.md     rizin / rz-bin playbook (DEX, strings, .so hardening)
├── .mcp.json            jadx MCP server, stdio transport, APK preloaded
├── AGENTS.md            the six-phase analysis spec
└── files.apk            the target
```

Then one one-shot agent run per APK:

```
mcode exec --cwd <workspace> --permission full \
           --output-format json --output-schema findings.schema.json \
           -o last_message.json --timeout 1800s -
```

`--output-schema` puts mcode into **native strict structured output**, so the
final answer arrives as a JSON object that already satisfies the schema — no
regex scraping, no prose parsing. Everything the orchestrator produces
(raw stdout, last message, findings JSON) lands in a sidecar `.meta/` directory
so the workspace stays clean and reusable.

### The two injected tools

| Tool | Transport | Role |
|---|---|---|
| **jadx** (`jadx-headless-mcp`) | stdio MCP | Decompiled Java/Kotlin, decoded `AndroidManifest.xml`, smali, resources, cross-references, call graphs. 35 tools. |
| **rizin-re** (skill) | markdown | `rz-bin` over `classes*.dex` and `lib/*/*.so`: Dalvik structure, string mining, ELF hardening audit. Fallback wherever jadx is blind. |

They fail in different places, which is the point. jadx gives readable logic;
rizin catches packed DEX, dynamically loaded code, native libraries, and the
string pool jadx's index does not surface.

---

## Install

```bash
# 1. rizin  (DEX + ELF analysis)
curl -LO https://github.com/rizinorg/rizin/releases/download/v0.9.1/rizin-v0.9.1-static-x86_64.tar.xz
mkdir -p ~/.local/opt/rizin && tar -xJf rizin-v0.9.1-static-x86_64.tar.xz -C ~/.local/opt/rizin
ln -sf ~/.local/opt/rizin/bin/* ~/.local/bin/

# 2. jadx-headless-mcp  (decompiler MCP server, stdio)
npm install -g jadx-headless-mcp@0.7.0

# 3. apkre itself
git clone <this repo> ~/SheepWool && ln -sf ~/SheepWool/bin/apkre ~/.local/bin/apkre
```

`apkre` needs only Python 3.10+ — no pip packages. Java 11+ and Node 18+ are
required by the jadx MCP.

Verify everything:

```bash
apkre doctor
```

---

## Usage

```bash
apkre doctor                       # check the toolchain
apkre scan ~/apks                 # list APKs, spend no tokens
apkre stage ~/apks                # build workspaces only, run no agent
apkre run ~/apks -c 8              # analyse everything, 8 at a time
apkre run ~/apks --limit 5         # first five
apkre run ~/apks --focus crypto,tamper
apkre run ~/apks --dry-run         # show the exact command, invoke nothing
apkre report out                  # rebuild summary.json from results.jsonl
```

### Useful options

| Flag | Effect |
|---|---|
| `-c, --concurrency N` | APKs in flight at once (default 4) |
| `--limit N` | stop after N APKs |
| `--timeout S` | per-APK agent budget (default 2700) |
| `--retries N` | retries on retryable failures (default 2) |
| `--no-resume` | re-analyse APKs that already succeeded |
| `--clean` | delete each workspace after analysis |
| `--copy` | copy the APK in instead of symlinking |
| `--no-autoload` | let the agent call `load_apk` itself |
| `--model` / `--effort` | override model or reasoning effort |
| `--fail-fast` | stop the batch on the first failure |

Resume is **content-addressed**: state is keyed by APK sha256, so re-running
against the same corpus skips what already succeeded even if files were moved
or renamed. Progress is appended to `results.jsonl` as each APK finishes, so an
interrupted batch loses nothing.

### Expect it to be slow

A full six-phase analysis of a 10–100 MB app is tens of minutes: JADX indexes
lazily under its own budget, and the agent makes many MCP round-trips. The
default budget is 45 min per APK. If runs start failing with `TIMEOUT`, raise
`--timeout` rather than lowering it — and prefer `-c` to raise throughput, since
these runs are almost entirely waiting on the model and on JADX.


---

## Output

```
apkre-out/
├── results.jsonl              one JSON record per APK (streamed as it goes)
├── summary.json               counts, risk distribution, token totals
├── findings.schema.json       the schema handed to the agent
├── state.db                   SQLite run state (resume)
├── reports/
│   └── files-2fe900bf43d7.md  human-readable report per APK
├── workspaces/                the staged workspaces
└── .meta/                     raw stdout, prompts, findings per APK
```

The report covers: risk score and rating, attack-surface findings ranked by
severity, exported components, permissions of note, network endpoints, redacted
secrets, cryptography, anti-analysis, native hardening gaps, third-party SDKs,
data access, suggested dynamic follow-ups, and honest `unknowns`.

### The schema

Driven by `apkre/schema.py` — fully inlined with `additionalProperties: false`
because native strict mode does not resolve `$ref`. `risk_score` is 0–100,
`risk_level` and every severity use closed enums, and `secrets[].redacted_value`
is masked by instruction so reports never carry a live credential.

---

## Design notes

**Why no pre-processing.** An earlier version extracted and analysed each APK up
front, then handed the agent a summary. It was removed deliberately: it burned
deterministic work that the agent does better with full context, and it made the
pipeline brittle when the pre-pass disagreed with the decompiler. The
orchestrator now only stages files; the agent does the analysis.

**Why `.mcp.json` sits at the workspace root.** The skill lives in `.agents/`,
as asked. MCP config could not: the runtime reads project MCP config from
`<root>/.mcp.json` specifically (plugin-scoped `mcp.json` only works inside an
Agent Plugin directory, which `mcode exec` has no flag to load). So the
workspace is `.agents/` + `AGENTS.md` + the APK, plus that one small spec
conforming config file.

**Why one-shot.** Each APK is a fresh `mcode exec` with its own session. No
resume, no shared history, no cross-contamination between targets, and a crashed
run cannot poison the next one. The envelope (`runId`, `usage`, `durationMs`) is
recorded per run for token accounting.

**Prompt delivery.** The prompt goes in on stdin, requested with `--input -`.
A bare positional `-` is *not* stdin — `mcode` reads it as a literal dash and
runs with an empty prompt, which surfaces only as a confusing
`STRUCTURED_OUTPUT_INVALID` because the model then improvises against the schema
with no task. Worth knowing before you touch `provider.py`.

**Structured output, and a limitation worth knowing.** `--output-schema` puts
mcode into native strict mode, so the answer arrives pre-validated. In practice
this MiniMax model **rejects native strict output as the schema grows**: a
2-property schema succeeds reliably, while the 20-property findings schema
fails with `STRUCTURED_OUTPUT_INVALID` even on a trivial task, where the model
happily emits 600 tokens and the response is discarded. So the text-mode
fallback is not theoretical — it is what actually carries the full schema.

To keep that from costing minutes, a strict failure is **not retried**: the
provider goes straight to a text-mode run with the contract inlined as a
concrete skeleton, extracts the JSON itself (brace-balanced scan that survives
code fences and braces inside strings), and runs the same validator. Every
record reports which path produced it in `mode`:

| `mode` | meaning |
|---|---|
| `native-strict` | the model honoured `--output-schema` |
| `text-fallback` | strict was rejected; JSON was extracted from a text reply |

If you are ever on a provider where native strict works well, the fallback path
simply stops triggering and nothing else changes.



---

## Layout

```
apkre/
├── cli.py         argparse CLI: doctor / scan / stage / run / report
├── apk.py         discovery, hashing, bundle handling
├── workspace.py   builds the per-APK workspace
├── schema.py      the structured-output contract + agent prompt
├── provider.py    mcode exec adapter, envelope parsing, retries
├── runner.py      concurrency, resume, result assembly
├── store.py       SQLite state
├── report.py      Markdown / JSONL / summary rendering
└── templates/
    ├── AGENTS.md      the analysis spec injected per APK
    └── skill-rizin.md the rizin skill injected per APK
```

## Extending

- **Different agent.** Implement the same `run_once` / envelope contract as
  `McodeProvider` in `provider.py` and swap it in `Runner.__init__`.
- **Different findings.** Edit `apkre/schema.py`; the prompt, validation and
  Markdown report all follow. Keep objects fully inlined for native strict mode.
- **Different skill.** Edit `apkre/templates/skill-rizin.md`. Skill names must
  be lowercase alphanumeric with single hyphens, no `--`.
