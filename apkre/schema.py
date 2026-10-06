"""The structured-output contract handed to the agent.

`mcode exec --output-schema` runs in ``native_strict`` mode, so the schema is
fully inlined (no ``$ref``/``$defs``) and every object sets
``additionalProperties: false``.
"""

from __future__ import annotations

import json
from typing import Any

RISK = {"type": "string", "enum": ["low", "medium", "high", "critical"]}
SEVERITY = {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]}
CONFIDENCE = {"type": "string", "enum": ["low", "medium", "high"]}


def _obj(props: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": props,
        "required": required if required is not None else list(props.keys()),
        "additionalProperties": False,
    }


FINDINGS_SCHEMA: dict[str, Any] = _obj(
    {
        "package_name": {"type": "string", "description": "Android package name, or empty string if unknown."},
        "version_name": {"type": "string"},
        "app_label": {"type": "string", "description": "Human-readable app name; resolve resource refs if possible."},
        "summary": {"type": "string", "description": "3-6 sentence analyst summary of what this app is and its risk posture."},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "risk_level": RISK,
        "confidence": CONFIDENCE,
        "app_purpose": {"type": "string", "description": "Inferred purpose and category of the app."},
        "permissions": {
            "type": "array",
            "description": "Only permissions worth calling out. Group trivial ones.",
            "items": _obj(
                {
                    "name": {"type": "string"},
                    "risk": RISK,
                    "reason": {"type": "string", "description": "Why this permission matters for this app."},
                }
            ),
        },
        "exported_components": {
            "type": "array",
            "description": "Components reachable by other apps. Empty array if none.",
            "items": _obj(
                {
                    "name": {"type": "string"},
                    "type": {"type": "string", "enum": ["activity", "service", "receiver", "provider"]},
                    "intent_actions": {"type": "array", "items": {"type": "string"}},
                    "risk": RISK,
                    "reason": {"type": "string"},
                }
            ),
        },
        "attack_surface": {
            "type": "array",
            "description": "Concrete abuse scenarios, most severe first.",
            "items": _obj(
                {
                    "title": {"type": "string"},
                    "severity": SEVERITY,
                    "detail": {"type": "string"},
                }
            ),
        },
        "network": {
            **_obj(
                {
                    "endpoints": {
                        "type": "array",
                        "items": _obj(
                            {
                                "url": {"type": "string"},
                                "purpose": {"type": "string"},
                                "confidence": CONFIDENCE,
                            }
                        ),
                    },
                    "uses_cleartext": {"type": "boolean"},
                    "pinned_or_verified_tls": {"type": "boolean"},
                }
            )
        },
        "secrets": {
            "type": "array",
            "description": "Hardcoded credentials/keys. Redact the value; never output the full secret.",
            "items": _obj(
                {
                    "kind": {"type": "string", "description": "e.g. api_key, aws_key, jwt, password, private_key"},
                    "redacted_value": {"type": "string", "description": "Masked value, e.g. AKIA...WXYZ"},
                    "location": {"type": "string", "description": "Class/method or file where it was found."},
                    "severity": SEVERITY,
                }
            ),
        },
        "crypto": {
            "type": "array",
            "items": _obj(
                {
                    "algorithm": {"type": "string"},
                    "usage": {"type": "string"},
                    "weakness": {"type": "string"},
                    "severity": SEVERITY,
                }
            )
        },
        "anti_analysis": _obj(
            {
                "root_detection": {"type": "string", "description": "Technique used, or 'none observed'."},
                "emulator_detection": {"type": "string"},
                "anti_debug": {"type": "string"},
                "tamper_checks": {"type": "string"},
                "obfuscation": {"type": "string", "description": "ProGuard/R8, string encryption, packer, or none."},
                "packing_evidence": {"type": "string"},
            }
        ),
        "native_libraries": {
            "type": "array",
            "items": _obj(
                {
                    "name": {"type": "string"},
                    "arch": {"type": "string"},
                    "hardening_gaps": {
                        "type": "array",
                        "items": {"type": "string", "description": "e.g. stack canary disabled, not PIE, partial RELRO"},
                    },
                    "notes": {"type": "string"},
                }
            ),
        },
        "third_party_sdks": {
            "type": "array",
            "items": _obj(
                {
                    "name": {"type": "string"},
                    "purpose": {"type": "string"},
                    "privacy_risk": RISK,
                }
            ),
        },
        "data_access": {
            "type": "array",
            "description": "Sensitive data the app reads/writes and how.",
            "items": _obj(
                {
                    "data_type": {"type": "string"},
                    "mechanism": {"type": "string"},
                    "risk": RISK,
                }
            ),
        },
        "dynamic_analysis_plan": {
            "type": "array",
            "description": "Concrete runtime checks to run next, e.g. Frida scripts, hooks, traffic capture.",
            "items": {"type": "string"},
        },
        "unknowns": {
            "type": "array",
            "description": "What could not be determined statically and why.",
            "items": {"type": "string"},
        },
    }
)


SYSTEM_PREAMBLE = """\
You are a senior Android reverse engineer performing authorized static analysis.

Ground rules:
- Base every claim on evidence you actually observed in the files. The triage
  evidence pack in the workspace is produced by `rz-bin`; it is real but
  partial. Read triage.json first, then verify and extend it with your own
  `rz-bin` / `unzip` / `strings` commands. Re-run the tools yourself for any
  claim that matters.
- Never invent class names, URLs, keys, or CVEs. If you did not see it, put it
  in "unknowns" instead.
- Redact secrets: report kind, location and a masked value only.
- Prefer specifics over generalities. "com.foo.BarActivity is exported with no
  permission guard" beats "some components may be exported".

Output contract:
- Reply with ONLY a single JSON object that matches the supplied schema.
- No prose before or after, no markdown code fences, no explanation.
"""


def build_prompt(
    *,
    apk_name: str,
    apk_path: str,
    sha256: str,
    triage_digest: str,
    triage_file: str,
    focus: list[str] | None = None,
    max_words: int = 0,
) -> str:
    """Compose the per-APK analysis prompt."""
    parts = [
        SYSTEM_PREAMBLE,
        f"Analyse the Android APK `{apk_name}` located at `{apk_path}`.",
        f"sha256: {sha256}",
        "",
        "Triage evidence pack (generated by rz-bin before you started):",
        triage_digest,
        "",
        f"Full evidence, including every class list, URL, domain and detected",
        f"string, is on disk at `{triage_file}`. Read it before answering.",
    ]
    if focus:
        parts.append("")
        parts.append("Pay particular attention to: " + ", ".join(focus) + ".")
    if max_words:
        parts.append("")
        parts.append(
            f'Keep "summary" and every "reason"/"detail" field under {max_words} words total.'
        )
    parts.append("")
    parts.append("Return the JSON object now.")
    return "\n".join(parts)


def schema_path(directory) -> "object":
    """Write FINDINGS_SCHEMA to *directory* and return the path."""
    from pathlib import Path

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / "findings.schema.json"
    p.write_text(json.dumps(FINDINGS_SCHEMA, indent=2), encoding="utf-8")
    return p


# --- text-mode fallback ----------------------------------------------------
#
# `mcode exec --output-schema` uses native strict structured output, which the
# backend can transiently reject (STRUCTURED_OUTPUT_INVALID) even while plain
# text replies succeed. When that happens we retry without the schema and hand
# the model a concrete skeleton instead, then validate the result ourselves.


def _skeleton(spec: dict) -> Any:
    t = spec.get("type")
    if t == "object":
        return {k: _skeleton(v) for k, v in spec.get("properties", {}).items()}
    if t == "array":
        return [_skeleton(spec.get("items", {"type": "string"}))]
    if "enum" in spec:
        return spec["enum"][0]
    return {
        "integer": 0,
        "number": 0,
        "boolean": False,
        "string": "",
    }.get(t, "")


def skeleton() -> dict:
    """A filled-in example object showing the exact required shape."""
    return _skeleton(FINDINGS_SCHEMA)


def schema_hint() -> str:
    """Compact, model-readable rendering of the contract for text mode."""
    return (
        "Return a single JSON object with exactly these keys, matching these "
        "types. Every key is required; use [] for empty lists and \"\" for "
        "unknown strings.\n\n"
        + json.dumps(skeleton(), indent=2, ensure_ascii=False)
        + "\n\nEnumerations: risk_level and risk = "
        + "low|medium|high|critical; severity = info|low|medium|high|critical; "
        "confidence = low|medium|high; exported_components[].type = "
        "activity|service|receiver|provider."
    )
