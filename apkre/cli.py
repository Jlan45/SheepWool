"""apkre — batch Android APK static analysis driven by the mcode CLI."""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
from pathlib import Path

from . import __version__
from . import report as reporting
from . import workspace as ws
from .apk import discover, inventory
from .runner import Config, Runner
from .store import Store

BANNER = "apkre · batch APK reverse engineering via mcode"


# --------------------------------------------------------------------------
# helpers


def _log(msg: str) -> None:
    print(msg, flush=True)


def _run_async(coro) -> int:
    try:
        return asyncio.run(coro)
    except KeyboardInterrupt:
        _log("\ninterrupted — progress is saved; re-run to resume")
        return 130


def _tool_row(name: str, cmd: str | None, note: str = "") -> None:
    mark = "✓" if cmd else "✗"
    _log(f"  {mark} {name:<22} {cmd or note}")


def cmd_doctor(_args: argparse.Namespace) -> int:
    _log(BANNER)
    _log(f"version {__version__}\n")
    _log("toolchain")
    _tool_row("mcode", shutil.which("mcode"))
    jadx_mcp, note = ws.resolve_jadx_command()
    _tool_row("jadx-headless-mcp", jadx_mcp, note)
    _tool_row("jadx", shutil.which("jadx"))
    _tool_row("rz-bin", shutil.which("rz-bin"), "rizin front-end")
    _tool_row("rizin", shutil.which("rizin"))
    _tool_row("java", shutil.which("java"))
    _tool_row("node", shutil.which("node"))
    _tool_row("unzip", shutil.which("unzip"))
    _log("")
    if not jadx_mcp:
        _log("  install it with:  npm install -g jadx-headless-mcp@0.7.0")
    if not shutil.which("rz-bin"):
        _log("  install rizin from https://github.com/rizinorg/rizin")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    apks = discover(args.directory, recursive=not args.no_recursive,
                    include_bundles=not args.no_bundles)
    if args.limit:
        apks = apks[: args.limit]
    if not apks:
        _log("no APKs found")
        return 2
    _log(f"{len(apks)} APK(s)\n")
    for a in apks:
        inv = inventory(a)
        abis = ",".join(inv.abis) or "-"
        _log(
            f"  {a.name}  {a.size/1e6:.1f}MB  dex={len(inv.dex_files)} "
            f"so={len(inv.native_libs)} abi={abis}  {a.sha256[:12]}"
        )
        if inv.error:
            _log(f"      ! {inv.error}")
    total = sum(a.size for a in apks)
    _log(f"\ntotal {total/1e6:.1f} MB")
    return 0


def cmd_stage(args: argparse.Namespace) -> int:
    """Stage workspaces only — no agent, no tokens."""
    cfg = Config(
        input_dir=Path(args.directory),
        out_dir=Path(args.out),
        limit=args.limit,
        recursive=not args.no_recursive,
        include_bundles=not args.no_bundles,
        materialize=args.copy,
        autoload=not args.no_autoload,
    )
    apks = discover(
        cfg.input_dir, recursive=cfg.recursive, include_bundles=cfg.include_bundles
    )
    if cfg.limit:
        apks = apks[: cfg.limit]
    if not apks:
        _log("no APKs found")
        return 2
    jadx_mcp, note = ws.resolve_jadx_command()
    if not jadx_mcp:
        _log(f"WARNING: {note}")
    _log(f"staging {len(apks)} workspace(s) into {cfg.out_dir / 'workspaces'}\n")
    for apk in apks:
        label = "".join(
            c if c.isalnum() or c in "._-" else "_" for c in apk.stem
        )[:48]
        work = cfg.out_dir / "workspaces" / f"{label}-{apk.sha256[:12]}"
        ws.build_workspace(
            work,
            apk.path,
            apk.name,
            apk.sha256,
            apk.size,
            jadx_command=jadx_mcp,
            java_bin=shutil.which("java"),
            materialize=cfg.materialize,
            autoload=cfg.autoload,
        )
        _log(f"  ✓ {work}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    focus = [f.strip() for f in (args.focus or "").split(",") if f.strip()]
    cfg = Config(
        input_dir=Path(args.directory),
        out_dir=Path(args.out),
        concurrency=args.concurrency,
        limit=args.limit,
        recursive=not args.no_recursive,
        include_bundles=not args.no_bundles,
        resume=not args.no_resume,
        materialize=args.copy,
        autoload=not args.no_autoload,
        keep_workspace=not args.clean,
        focus=focus,
        retries=args.retries,
        timeout=args.timeout,
        max_steps=args.max_steps,
        model=args.model,
        effort=args.effort,
        permission=args.permission,
        prompt_mode=args.prompt_mode,
        fail_fast=args.fail_fast,
        dry_run=args.dry_run,
        on_progress=None if args.quiet else _log,
    )

    runner = Runner(cfg)
    _log(BANNER)
    _log(f"input   {cfg.input_dir}")
    _log(f"output  {cfg.out_dir}")
    _log(f"agent   mcode (one-shot, schema-constrained) · concurrency {cfg.concurrency}")
    if cfg.timeout:
        _log(f"timeout {cfg.timeout}s per APK")
    _log("")

    with Store(cfg.out_dir / "state.db") as store:
        store.set_meta("input_dir", str(cfg.input_dir))
        code = _run_async(runner.run(store))
        summary = runner.finalize(store)

    if args.dry_run:
        _log("\ndry run — no agent was invoked\n")
        for r in runner.records:
            _log(f"  {r['name']}")
            _log(f"    cwd    {r['workspace']['root']}")
            _log(f"    cmd    {' '.join(r['command'])}")
        return 0

    _log("")
    _log(
        f"done — {summary['succeeded']}/{summary['total']} succeeded"
        + (f", {summary['failed']} failed" if summary.get("failed") else "")
    )
    if summary.get("by_risk_level"):
        _log("  risk: " + " · ".join(f"{k}={v}" for k, v in sorted(summary["by_risk_level"].items())))
    t = summary.get("tokens", {})
    _log(f"  tokens: {t.get('total_tokens', 0):,} total")
    _log(f"  results: {cfg.out_dir / 'results.jsonl'}")
    _log(f"  summary: {cfg.out_dir / 'summary.json'}")
    _log(f"  reports: {cfg.out_dir / 'reports'}")
    return code


def cmd_report(args: argparse.Namespace) -> int:
    out = Path(args.out)
    jsonl = out / "results.jsonl"
    if not jsonl.exists():
        _log(f"no results.jsonl in {out}")
        return 2
    records = [json.loads(l) for l in jsonl.read_text(encoding="utf-8").splitlines() if l.strip()]
    with Store(out / "state.db") as store:
        summary = reporting.build_summary(records, store.counts(), store.token_totals())
    reporting.write_summary(out, summary)
    _log(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


# --------------------------------------------------------------------------
# parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apkre",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  apkre doctor                              check the toolchain
  apkre scan ~/apks                        list APKs, spend no tokens
  apkre stage ~/apks --out out              build workspaces only
  apkre run ~/apks -c 8                     analyse everything, 8 at a time
  apkre run ~/apks --limit 5 --focus crypto,tamper
  apkre run ~/apks --dry-run                show commands, invoke nothing

Each APK gets its own workspace holding only: .agents/ (skill), .mcp.json
(jadx MCP), AGENTS.md (task flow), and the APK itself.
""",
    )
    p.add_argument("--version", action="version", version=f"apkre {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="check the toolchain").set_defaults(func=cmd_doctor)

    sp = sub.add_parser("scan", help="list discovered APKs")
    sp.add_argument("directory")
    sp.add_argument("--limit", type=int)
    sp.add_argument("--no-recursive", action="store_true")
    sp.add_argument("--no-bundles", action="store_true",
                    help="ignore XAPK/APKS bundles")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("stage", help="build workspaces without running the agent")
    sp.add_argument("directory")
    sp.add_argument("-o", "--out", default="apkre-out")
    sp.add_argument("--limit", type=int)
    sp.add_argument("--no-recursive", action="store_true")
    sp.add_argument("--no-bundles", action="store_true")
    sp.add_argument("--copy", action="store_true",
                    help="copy the APK in instead of symlinking")
    sp.add_argument("--no-autoload", action="store_true",
                    help="let the agent call load_apk itself")
    sp.set_defaults(func=cmd_stage)

    sp = sub.add_parser("run", help="analyse every APK with the mcode agent")
    sp.add_argument("directory")
    sp.add_argument("-o", "--out", default="apkre-out")
    sp.add_argument("-c", "--concurrency", type=int, default=4)
    sp.add_argument("--limit", type=int)
    sp.add_argument("--no-recursive", action="store_true")
    sp.add_argument("--no-bundles", action="store_true")
    sp.add_argument("--no-resume", action="store_true",
                    help="re-analyse APKs that already succeeded")
    sp.add_argument("--copy", action="store_true")
    sp.add_argument("--no-autoload", action="store_true")
    sp.add_argument("--clean", action="store_true",
                    help="delete each workspace after its analysis")
    sp.add_argument("--model", help="provider/model for this run")
    sp.add_argument("--effort", choices=["low", "medium", "high", "max"])
    sp.add_argument("--timeout", type=int, default=2700,
                    help="seconds per APK (default 45min; deep analysis is slow)")
    sp.add_argument("--max-steps", type=int)
    sp.add_argument("--retries", type=int, default=2)
    sp.add_argument("--focus", help="comma-separated areas to emphasise")
    sp.add_argument("--permission", default="full",
                    choices=["smart", "full", "off"])
    sp.add_argument("--prompt-mode", default="work",
                    choices=["tui", "coding", "work"])
    sp.add_argument("--fail-fast", action="store_true")
    sp.add_argument("--dry-run", action="store_true",
                    help="stage workspaces and print commands, invoke nothing")
    sp.add_argument("-q", "--quiet", action="store_true")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("report", help="rebuild summary.json from results.jsonl")
    sp.add_argument("-o", "--out", default="apkre-out")
    sp.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
