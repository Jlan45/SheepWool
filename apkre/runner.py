"""Batch orchestration: discover -> stage workspace -> agent -> structured result.

The per-APK workspace is left exactly as staged: `.agents/`, `.mcp.json`,
`AGENTS.md` and the APK. Everything the orchestrator produces (raw stdout,
last message, findings JSON) goes to a sidecar ``.meta/`` directory so the
workspace stays clean and reusable.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import report as reporting
from . import schema as schema_mod
from . import workspace as ws
from .apk import ApkFile, discover
from .provider import McodeProvider, RunResult
from .store import Store

Progress = Callable[[str], None]


@dataclass
class Config:
    input_dir: Path
    out_dir: Path
    concurrency: int = 4
    limit: int | None = None
    recursive: bool = True
    include_bundles: bool = True
    resume: bool = True
    materialize: bool = False
    autoload: bool = True
    keep_workspace: bool = True
    focus: list[str] = field(default_factory=list)
    retries: int = 2
    timeout: int = 2700
    max_steps: int | None = None
    model: str | None = None
    effort: str | None = None
    permission: str = "full"
    prompt_mode: str = "work"
    fail_fast: bool = False
    dry_run: bool = False
    on_progress: Progress | None = None


# AGENTS.md is auto-loaded into the agent's context, so the runtime prompt stays
# deliberately short: point at the spec, state the tool contract, demand JSON.
RUNTIME_PROMPT = """\
Perform the APK static analysis specified in AGENTS.md, for the target in this
workspace: {apk}

Your tooling is already configured:
  - MCP server `jadx` — a headless JADX decompiler, preloaded with this APK.
    Call `index_status` first: it indexes lazily, so work with what is indexed
    now and re-check later rather than blocking.
  - Skill `rizin-re` — read it before using rizin/rz-bin. Use it for Dalvik
    structure, string mining, and native .so hardening whenever jadx is blind.

Follow the six phases in AGENTS.md in order. Ground every claim in evidence you
actually observed, and put anything you could not determine in `unknowns`.

Then return the final answer as a single JSON object matching the supplied
schema: first character `{{`, last character `}}`, no code fences, no prose.
"""


def validate_output(obj: Any) -> list[str]:
    """Structural check on the agent's object.

    mcode runs the schema natively, so this mostly catches salvaged payloads
    from a retried or partially-failed run.
    """
    if not isinstance(obj, dict):
        return ["output is not a JSON object"]
    problems: list[str] = []
    sch = schema_mod.FINDINGS_SCHEMA
    for key in sch.get("required", []):
        if key not in obj:
            problems.append(f"missing key: {key}")
    if problems:
        return problems
    for key, spec in sch["properties"].items():
        val = obj.get(key)
        if "enum" in spec and isinstance(val, str) and val not in spec["enum"]:
            problems.append(f"{key}={val!r} not in {spec['enum']}")
        if spec.get("type") == "array" and not isinstance(val, list):
            problems.append(f"{key} should be an array")
    rs = obj.get("risk_score")
    if not isinstance(rs, int) or not (0 <= rs <= 100):
        problems.append("risk_score must be an int 0..100")
    return problems


class Runner:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        # Absolute out_dir: the workspace path is handed to the MCP server and
        # to `mcode exec --cwd`, so it must not depend on the caller's cwd.
        self.cfg.out_dir = Path(cfg.out_dir).expanduser().resolve()
        self.cfg.out_dir.mkdir(parents=True, exist_ok=True)
        self.schema_file = schema_mod.schema_path(self.cfg.out_dir)
        self.provider = McodeProvider(
            model=cfg.model,
            effort=cfg.effort,
            max_steps=cfg.max_steps,
            timeout=cfg.timeout,
            permission=cfg.permission,
            prompt_mode=cfg.prompt_mode,
            retries=cfg.retries,
        )
        self.jadx_command, self.jadx_note = ws.resolve_jadx_command()
        self.java_bin = shutil.which("java")
        self.records: list[dict] = []
        self._stop = False

    def log(self, msg: str) -> None:
        if self.cfg.on_progress:
            self.cfg.on_progress(msg)

    def discover(self) -> list[ApkFile]:
        apks = discover(
            self.cfg.input_dir,
            recursive=self.cfg.recursive,
            include_bundles=self.cfg.include_bundles,
        )
        if self.cfg.limit:
            apks = apks[: self.cfg.limit]
        return apks

    def _paths(self, apk: ApkFile) -> tuple[Path, Path]:
        label = "".join(
            c if c.isalnum() or c in "._-" else "_" for c in apk.stem
        )[:48]
        work = self.cfg.out_dir / "workspaces" / f"{label}-{apk.sha256[:12]}"
        meta = self.cfg.out_dir / ".meta" / f"{label}-{apk.sha256[:12]}"
        return work, meta

    async def process(self, apk: ApkFile, store: Store) -> dict:
        workdir, meta_dir = self._paths(apk)
        meta_dir.mkdir(parents=True, exist_ok=True)

        rec: dict[str, Any] = {
            "name": apk.name,
            "path": str(apk.path),
            "sha256": apk.sha256,
            "size": apk.size,
        }

        # 1. stage the workspace: .agents/ + .mcp.json + AGENTS.md + apk
        space = await asyncio.to_thread(
            ws.build_workspace,
            workdir,
            apk.path,
            apk.name,
            apk.sha256,
            apk.size,
            jadx_command=self.jadx_command,
            java_bin=self.java_bin,
            materialize=self.cfg.materialize,
            autoload=self.cfg.autoload,
        )
        rec["workspace"] = space.describe()

        # 2. run the agent
        prompt = RUNTIME_PROMPT.format(apk=apk.name)
        (meta_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
        last_msg = meta_dir / "last_message.json"
        store.mark_running(apk.sha256, self.provider.name, self.cfg.model)

        if self.cfg.dry_run:
            rec["status"] = "dry-run"
            rec["prompt"] = prompt
            rec["command"] = self.provider.build_command(
                "<prompt on stdin>",
                cwd=workdir,
                schema_file=self.schema_file,
                last_message=last_msg,
            )
            return rec

        t0 = time.time()
        result: RunResult = await asyncio.to_thread(
            self.provider.run,
            prompt,
            cwd=workdir,
            schema_file=self.schema_file,
            last_message=last_msg,
            validate=validate_output,
            fallback_hint=schema_mod.schema_hint(),
        )
        wall = time.time() - t0
        (meta_dir / "raw_stdout.txt").write_text(result.raw or "", encoding="utf-8")

        rec["attempt"] = result.attempt
        rec["mode"] = result.mode
        rec["duration_ms"] = result.duration_ms or int(wall * 1000)
        rec["wall_seconds"] = round(wall, 1)
        rec["usage"] = result.usage
        rec["model"] = result.model.get("modelId") if result.model else None
        rec["run_id"] = result.run_id
        rec["session_id"] = result.session_id

        if not result.ok:
            rec["status"] = "failed"
            rec["error_code"] = result.error_code
            rec["error_message"] = result.error_message
            rec["validation_errors"] = result.validation_errors
            store.mark_failed(
                apk.sha256,
                code=result.error_code,
                message=result.error_message,
                duration_ms=rec["duration_ms"],
            )
            return rec

        out = result.output or {}
        rec["status"] = "succeeded"
        rec["output"] = out
        (meta_dir / "findings.json").write_text(
            json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        md = reporting.write_report(
            self.cfg.out_dir,
            apk=rec,
            output=out,
            provider=self.provider.name,
            model=rec["model"],
            usage=result.usage,
            duration_ms=rec["duration_ms"],
            attempts=result.attempt,
        )
        rec["report"] = str(md)
        store.mark_succeeded(
            apk.sha256,
            output=out,
            usage=result.usage,
            duration_ms=rec["duration_ms"],
            provider=self.provider.name,
            model=rec["model"],
            report_path=str(md),
        )

        if not self.cfg.keep_workspace:
            shutil.rmtree(workdir, ignore_errors=True)
            rec["workspace_removed"] = True
        return rec

    async def run(self, store: Store) -> int:
        apks = self.discover()
        if not apks:
            self.log("no APKs found")
            return 2

        store.register(apks)
        done = store.succeeded_shas() if self.cfg.resume else set()
        if not self.cfg.resume:
            for apk in apks:
                store.mark_reset(apk.sha256)
        todo = [a for a in apks if a.sha256 not in done]
        self.log(
            f"{len(apks)} APK(s) found · {len(done)} already done · {len(todo)} queued"
        )

        ok, note = self.provider.available()
        if not ok and not self.cfg.dry_run:
            self.log(f"ERROR: {note}")
            return 3
        if not self.jadx_command:
            self.log(f"WARNING: {self.jadx_note} — the agent will have no jadx MCP")

        sem = asyncio.Semaphore(max(1, self.cfg.concurrency))
        jsonl = self.cfg.out_dir / "results.jsonl"
        jsonl.touch()

        async def worker(apk: ApkFile) -> None:
            async with sem:
                if self._stop:
                    return
                self.log(f"▶ {apk.name}")
                try:
                    rec = await self.process(apk, store)
                except Exception as exc:  # noqa: BLE001 - never kill the batch
                    rec = {
                        "name": apk.name,
                        "path": str(apk.path),
                        "sha256": apk.sha256,
                        "size": apk.size,
                        "status": "failed",
                        "error_code": "ORCHESTRATOR",
                        "error_message": f"{type(exc).__name__}: {exc}",
                    }
                    store.mark_failed(
                        apk.sha256, code="ORCHESTRATOR", message=str(exc), duration_ms=0
                    )
                self.records.append(rec)
                with jsonl.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                self._log_result(rec)
                if self.cfg.fail_fast and rec.get("status") == "failed":
                    self._stop = True

        await asyncio.gather(*(worker(a) for a in todo))
        return 0

    def _log_result(self, rec: dict) -> None:
        st = rec.get("status")
        if st == "succeeded":
            o = rec.get("output") or {}
            self.log(
                f"  ✓ {rec.get('name')} risk={o.get('risk_score')}"
                f"/{o.get('risk_level')} · {rec.get('wall_seconds', 0):.0f}s · "
                f"{rec.get('usage', {}).get('totalTokens', 0):,} tok"
            )
        elif st == "failed":
            self.log(
                f"  ✗ {rec.get('name')} [{rec.get('error_code')}] "
                f"{(rec.get('error_message') or '')[:160]}"
            )
        else:
            self.log(f"  · {rec.get('name')} {st}")

    def finalize(self, store: Store) -> dict:
        summary = reporting.build_summary(
            self.records, store.counts(), store.token_totals()
        )
        reporting.write_summary(self.cfg.out_dir, summary)
        return summary
