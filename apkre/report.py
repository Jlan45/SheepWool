"""Result rendering: per-APK Markdown, results.jsonl and summary.json."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

RISK_BADGE = {
    "critical": "🔴 CRITICAL",
    "high": "🟠 HIGH",
    "medium": "🟡 MEDIUM",
    "low": "🟢 LOW",
}

SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:80]


def _rows(items: Any, key: str) -> list[dict]:
    """Drop blank/placeholder rows so a half-filled payload cannot render junk."""
    if not isinstance(items, list):
        return []
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        val = it.get(key)
        if val is None or (isinstance(val, str) and not val.strip()):
            continue
        out.append(it)
    return out


def _text(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    return [s.strip() for s in items if isinstance(s, str) and s.strip()]


def render_markdown(
    *,
    apk: dict,
    output: dict,
    provider: str,
    model: str | None,
    usage: dict,
    duration_ms: int,
    attempts: int,
) -> str:
    L: list[str] = []
    a = L.append

    pkg = output.get("package_name") or "?"
    level = output.get("risk_level") or "unknown"
    score = output.get("risk_score")

    a(f"# {apk.get('name', 'apk')}")
    a("")
    a(f"**{RISK_BADGE.get(level, level.upper())}** — risk score {score}/100 "
      f"· confidence {output.get('confidence', 'unknown')}")
    a("")
    a(f"- Package: `{pkg}`")
    a(f"- Version: {output.get('version_name') or '?'}")
    a(f"- Label: {output.get('app_label') or '—'}")
    a(f"- Source: `{apk.get('path')}`")
    a(f"- sha256: `{apk.get('sha256')}`")
    a(f"- Size: {_human(apk.get('size') or 0)}")
    a(f"- Analysis: {provider}"
      f"{f' · {model}' if model else ''} · {attempts} attempt(s) · {duration_ms/1000:.1f}s · "
      f"{usage.get('inputTokens', 0):,} in / {usage.get('outputTokens', 0):,} out tokens")
    a("")

    if output.get("app_purpose"):
        a("## Purpose")
        a("")
        a(output["app_purpose"])
        a("")

    if output.get("summary"):
        a("## Summary")
        a("")
        a(output["summary"])
        a("")

    findings = _rows(output.get("attack_surface"), "title")
    if findings:
        a("## Attack surface")
        a("")
        for f in findings:
            icon = SEVERITY_ICON.get(f.get("severity", "info"), "•")
            a(f"### {icon} {f.get('title', 'finding')} ({f.get('severity', '?')})")
            a("")
            a(f.get("detail", ""))
            a("")

    perms = _rows(output.get("permissions"), "name")
    if perms:
        a("## Permissions of note")
        a("")
        a("| Permission | Risk | Why |")
        a("|---|---|---|")
        for p in perms:
            a(f"| `{p.get('name','')}` | {p.get('risk','')} | {p.get('reason','')} |")
        a("")

    exported = _rows(output.get("exported_components"), "name")
    if exported:
        a("## Exported components")
        a("")
        a("| Component | Type | Risk | Actions | Why |")
        a("|---|---|---|---|---|")
        for c in exported:
            acts = ", ".join(c.get("intent_actions") or []) or "—"
            a(f"| `{c.get('name','')}` | {c.get('type','')} | {c.get('risk','')} "
              f"| {acts} | {c.get('reason','')} |")
        a("")

    net = output.get("network") or {}
    eps = _rows(net.get("endpoints"), "url")
    if eps:
        a("## Network endpoints")
        a("")
        a(f"Cleartext HTTP: {'yes' if net.get('uses_cleartext') else 'no/not observed'} · "
          f"TLS verification: {'pinned or verified' if net.get('pinned_or_verified_tls') else 'not verified'}")
        a("")
        a("| URL | Purpose | Confidence |")
        a("|---|---|---|")
        for e in eps[:60]:
            a(f"| `{e.get('url','')}` | {e.get('purpose','')} | {e.get('confidence','')} |")
        a("")

    secrets = _rows(output.get("secrets"), "kind")
    if secrets:
        a("## Hardcoded secrets")
        a("")
        a("| Kind | Value | Location | Severity |")
        a("|---|---|---|---|")
        for s in secrets:
            a(f"| {s.get('kind','')} | `{s.get('redacted_value','')}` "
              f"| {s.get('location','')} | {s.get('severity','')} |")
        a("")

    crypto = _rows(output.get("crypto"), "algorithm")
    if crypto:
        a("## Cryptography")
        a("")
        a("| Algorithm | Usage | Weakness | Severity |")
        a("|---|---|---|---|")
        for c in crypto:
            a(f"| {c.get('algorithm','')} | {c.get('usage','')} | {c.get('weakness','')} "
              f"| {c.get('severity','')} |")
        a("")

    anti = output.get("anti_analysis") or {}
    if any(str(v).strip() for v in anti.values() if isinstance(v, str)):
        a("## Anti-analysis")
        a("")
        for k, label in (
            ("root_detection", "Root detection"),
            ("emulator_detection", "Emulator detection"),
            ("anti_debug", "Anti-debug"),
            ("tamper_checks", "Tamper checks"),
            ("obfuscation", "Obfuscation"),
            ("packing_evidence", "Packing"),
        ):
            if anti.get(k):
                a(f"- **{label}:** {anti[k]}")
        a("")

    natives = _rows(output.get("native_libraries"), "name")
    if natives:
        a("## Native libraries")
        a("")
        a("| Library | Arch | Hardening gaps | Notes |")
        a("|---|---|---|---|")
        for n in natives:
            gaps = ", ".join(n.get("hardening_gaps") or []) or "—"
            a(f"| `{n.get('name','')}` | {n.get('arch','')} | {gaps} | {n.get('notes','')} |")
        a("")

    sdks = _rows(output.get("third_party_sdks"), "name")
    if sdks:
        a("## Third-party SDKs")
        a("")
        a("| SDK | Purpose | Privacy risk |")
        a("|---|---|---|")
        for s in sdks:
            a(f"| {s.get('name','')} | {s.get('purpose','')} | {s.get('privacy_risk','')} |")
        a("")

    data = _rows(output.get("data_access"), "data_type")
    if data:
        a("## Data access")
        a("")
        a("| Data | Mechanism | Risk |")
        a("|---|---|---|")
        for d in data:
            a(f"| {d.get('data_type','')} | {d.get('mechanism','')} | {d.get('risk','')} |")
        a("")

    plan = _text(output.get("dynamic_analysis_plan"))
    if plan:
        a("## Suggested next steps (dynamic)")
        a("")
        for i, s in enumerate(plan, 1):
            a(f"{i}. {s}")
        a("")

    unknowns = _text(output.get("unknowns"))
    if unknowns:
        a("## Unknowns")
        a("")
        for u in unknowns:
            a(f"- {u}")
        a("")

    a("---")
    a("")
    a("_Generated by apkre. Facts in this report were produced by the analysis "
      "agent using jadx (MCP) and rizin._")
    a("")
    return "\n".join(L)


def _human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} GB"


def write_report(
    out_dir: Path,
    *,
    apk: dict,
    output: dict,
    provider: str,
    model: str | None,
    usage: dict,
    duration_ms: int,
    attempts: int,
) -> Path:
    reports = out_dir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    p = reports / f"{_safe(apk.get('name', 'apk'))}-{apk.get('sha256','')[:12]}.md"
    p.write_text(
        render_markdown(
            apk=apk,
            output=output,
            provider=provider,
            model=model,
            usage=usage,
            duration_ms=duration_ms,
            attempts=attempts,
        ),
        encoding="utf-8",
    )
    return p


def write_jsonl(out_dir: Path, records: list[dict]) -> Path:
    p = out_dir / "results.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    return p


def build_summary(records: list[dict], store_counts: dict, tokens: dict) -> dict:
    ok = [r for r in records if r.get("status") == "succeeded"]
    by_level: dict[str, int] = {}
    for r in ok:
        lvl = (r.get("output") or {}).get("risk_level", "unknown")
        by_level[lvl] = by_level.get(lvl, 0) + 1
    scores = [
        (r.get("output") or {}).get("risk_score")
        for r in ok
        if isinstance((r.get("output") or {}).get("risk_score"), int)
    ]
    findings: dict[str, int] = {}
    for r in ok:
        for f in (r.get("output") or {}).get("attack_surface") or []:
            key = f.get("severity", "info")
            findings[key] = findings.get(key, 0) + 1
    return {
        "total": len(records),
        "succeeded": len(ok),
        "failed": sum(1 for r in records if r.get("status") == "failed"),
        "by_risk_level": by_level,
        "highest_scores": sorted(scores, reverse=True)[:10],
        "mean_risk_score": round(sum(scores) / len(scores), 1) if scores else None,
        "attack_surface_findings_by_severity": findings,
        "tokens": tokens,
        "store_counts": store_counts,
    }


def write_summary(out_dir: Path, summary: dict) -> Path:
    p = out_dir / "summary.json"
    p.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return p
