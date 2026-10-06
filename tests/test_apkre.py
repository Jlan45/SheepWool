"""Stdlib-only tests:  python3 -m unittest discover -s tests -v"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apkre import schema as schema_mod  # noqa: E402
from apkre import workspace as ws  # noqa: E402
from apkre.apk import discover, inventory  # noqa: E402
from apkre.runner import validate_output  # noqa: E402

MCP_SCHEMA_URL = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"


def make_apk(path: Path, package: str = "com.example.demo") -> None:
    """A minimal but structurally valid APK (no real manifest needed here)."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 16)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        zf.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF" + b"\x00" * 32)
        zf.writestr("assets/config.json", "{}")
        zf.writestr("META-INF/CERT.RSA", b"x")
        zf.writestr("META-INF/CERT.SF", b"x")
        zf.writestr("lib/arm64-v8a/libfrida.so", b"\x7fELF")


class TestDiscovery(unittest.TestCase):
    def test_finds_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "nested").mkdir()
            a = root / "one.apk"
            b = root / "nested" / "two.apk"
            (root / "notapk.txt").write_text("x")
            make_apk(a)
            make_apk(b)
            found = discover(root)
            # Ordering is by path (deterministic, groups directories).
            self.assertEqual(sorted(f.name for f in found), ["one.apk", "two.apk"])
            self.assertEqual([f.name for f in found], ["two.apk", "one.apk"])
            self.assertTrue(all(len(f.sha256) == 64 for f in found))

    def test_inventory_contents(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.apk"
            make_apk(p)
            inv = inventory(discover(Path(d))[0])
            self.assertTrue(inv.ok)
            self.assertEqual(inv.dex_files, ["classes.dex"])
            self.assertEqual(inv.abis, ["arm64-v8a"])
            self.assertIn("arm64-v8a", {n.split("/")[1] for n in inv.native_libs})

    def test_ignores_broken_zip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "bad.apk"
            p.write_bytes(b"not a zip at all")
            inv = inventory(discover(Path(d))[0])
            self.assertFalse(inv.ok)
            self.assertIn("not a valid zip", inv.error or "")


class TestWorkspace(unittest.TestCase):
    def _build(self, d: str, **kw) -> ws.Workspace:
        src = Path(d) / "src.apk"
        make_apk(src)
        return ws.build_workspace(
            Path(d) / "ws",
            src,
            "demo.apk",
            "a" * 64,
            1234,
            jadx_command=kw.pop("jadx_command", "/usr/bin/jadx-headless-mcp"),
            java_bin="/usr/bin/java",
            **kw,
        )

    def test_layout_is_exactly_four_entries(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            space = self._build(d)
            top = sorted(p.name for p in space.root.iterdir())
            self.assertEqual(top, [".agents", ".mcp.json", "AGENTS.md", "demo.apk"])
            skill = space.skill_dir / "SKILL.md"
            self.assertTrue(skill.is_file())
            self.assertEqual(space.skill_dir.name, "rizin-re")
            self.assertEqual(space.skill_dir.parent.name, ".agents")

    def test_skill_frontmatter_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            text = (self._build(d).skill_dir / "SKILL.md").read_text()
            self.assertTrue(text.startswith("---\n"))
            fm = text.split("---", 2)[1]
            name = next(
                l.split(":", 1)[1].strip()
                for l in fm.splitlines()
                if l.startswith("name:")
            )
            desc = next(
                l.split(":", 1)[1].strip()
                for l in fm.splitlines()
                if l.startswith("description:")
            )
            # Runtime enforces this exact pattern.
            self.assertRegex(name, r"^(?!.*--)[a-z0-9]+(?:-[a-z0-9]+)*$")
            self.assertLessEqual(len(name), 64)
            self.assertLessEqual(len(desc), 1024)

    def test_mcp_config_matches_spec(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = json.loads((self._build(d).mcp_config).read_text())
            self.assertEqual(cfg["$schema"], MCP_SCHEMA_URL)
            self.assertEqual(set(cfg), {"$schema", "mcpServers"})
            server = cfg["mcpServers"]["jadx"]
            self.assertEqual(server["type"], "stdio")
            self.assertEqual(server["args"][0], "serve")
            self.assertIn("--apk", server["args"])
            self.assertTrue(set(server) <= {"type", "command", "args", "env",
                                           "description", "timeout", "tools"})
            # Server key must match the runtime's name pattern.
            self.assertRegex("jadx", r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")

    def test_agents_md_is_substituted(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            text = (self._build(d).agents_md).read_text()
            self.assertNotIn("{{APK_NAME}}", text)
            self.assertIn("demo.apk", text)
            self.assertIn("a" * 64, text)

    def test_apk_is_symlinked_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            space = self._build(d)
            self.assertTrue(space.apk_path.is_symlink())
            self.assertTrue(space.apk_path.exists())

    def test_materialize_copies(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            space = self._build(d, materialize=True)
            self.assertFalse(space.apk_path.is_symlink())
            self.assertTrue(space.apk_path.is_file())

    def test_rerun_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            a = self._build(d)
            b = self._build(d)
            self.assertEqual(
                sorted(p.name for p in a.root.iterdir()),
                sorted(p.name for p in b.root.iterdir()),
            )


class TestSchema(unittest.TestCase):
    def test_native_strict_shape(self) -> None:
        s = schema_mod.FINDINGS_SCHEMA
        self.assertEqual(s["additionalProperties"], False)
        self.assertEqual(set(s["required"]), set(s["properties"]))
        for name, spec in s["properties"].items():
            with self.subTest(field=name):
                # Scalar schemas have no additionalProperties by definition.
                if spec["type"] == "object":
                    self.assertFalse(spec.get("additionalProperties", True))
                if spec["type"] == "array":
                    items = spec["items"]
                    if items.get("type") == "object":
                        self.assertFalse(items.get("additionalProperties", True))

    def test_no_refs(self) -> None:
        # Native strict mode does not resolve $ref; keep it inline.
        blob = json.dumps(schema_mod.FINDINGS_SCHEMA)
        self.assertNotIn("$ref", blob)
        self.assertNotIn("$defs", blob)

    def test_risk_score_bounded(self) -> None:
        spec = schema_mod.FINDINGS_SCHEMA["properties"]["risk_score"]
        self.assertEqual((spec["minimum"], spec["maximum"]), (0, 100))


class TestValidator(unittest.TestCase):
    def _valid(self) -> dict:
        return {
            k: ([] if v.get("type") == "array" else
                0 if v.get("type") == "integer" else
                v["enum"][0] if "enum" in v else "")
            for k, v in schema_mod.FINDINGS_SCHEMA["properties"].items()
        }

    def test_accepts_minimal_valid(self) -> None:
        self.assertEqual(validate_output(self._valid()), [])

    def test_rejects_missing_keys(self) -> None:
        bad = self._valid()
        del bad["summary"]
        self.assertTrue(any("missing key" in p for p in validate_output(bad)))

    def test_rejects_bad_enum(self) -> None:
        bad = self._valid()
        bad["risk_level"] = "spicy"
        self.assertTrue(any("not in" in p for p in validate_output(bad)))

    def test_rejects_out_of_range_score(self) -> None:
        bad = self._valid()
        bad["risk_score"] = 900
        self.assertTrue(any("risk_score" in p for p in validate_output(bad)))

    def test_rejects_non_object(self) -> None:
        self.assertTrue(validate_output("nope"))


class TestReport(unittest.TestCase):
    def test_renders_all_sections(self) -> None:
        from apkre import report
        from apkre.schema import skeleton

        out = skeleton()
        out.update(
            {
                "package_name": "com.example.demo",
                "version_name": "1.2.3",
                "app_label": "Demo",
                "summary": "A demo app.",
                "risk_score": 73,
                "risk_level": "high",
                "confidence": "medium",
                "app_purpose": "Demo purposes.",
                "attack_surface": [
                    {"title": "Exported provider", "severity": "high", "detail": "d"}
                ],
                "secrets": [
                    {
                        "kind": "api_key",
                        "redacted_value": "AKIA...WXYZ",
                        "location": "BuildConfig",
                        "severity": "high",
                    }
                ],
                "unknowns": ["Native lib stripped."],
            }
        )
        with tempfile.TemporaryDirectory() as d:
            p = report.write_report(
                Path(d),
                apk={
                    "name": "demo.apk",
                    "path": "/tmp/demo.apk",
                    "sha256": "b" * 64,
                    "size": 5_000_000,
                },
                output=out,
                provider="mcode",
                model="M",
                usage={"inputTokens": 100, "outputTokens": 20},
                duration_ms=1234,
                attempts=1,
            )
            text = p.read_text()
            self.assertIn("# demo.apk", text)
            self.assertIn("🟠 HIGH", text)
            self.assertIn("73/100", text)
            self.assertIn("Exported provider", text)
            self.assertIn("AKIA...WXYZ", text)
            self.assertIn("Native lib stripped.", text)
            # Skeleton placeholders must not leak as blank table rows.
            self.assertNotIn("| `` |", text)

    def test_summary_counts(self) -> None:
        from apkre import report

        recs = [
            {"status": "succeeded", "output": {"risk_level": "high", "risk_score": 80,
                                               "attack_surface": [{"severity": "high"}]}},
            {"status": "succeeded", "output": {"risk_level": "low", "risk_score": 10,
                                               "attack_surface": []}},
            {"status": "failed", "error_code": "X"},
        ]
        s = report.build_summary(recs, {"succeeded": 2, "failed": 1},
                                 {"total_tokens": 500})
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["succeeded"], 2)
        self.assertEqual(s["failed"], 1)
        self.assertEqual(s["by_risk_level"], {"high": 1, "low": 1})
        self.assertEqual(s["mean_risk_score"], 45.0)
        self.assertEqual(s["highest_scores"], [80, 10])
        self.assertEqual(
            s["attack_surface_findings_by_severity"], {"high": 1}
        )


    def test_strict_failure_skips_remaining_strict_retries(self) -> None:
        """A rejected schema must not burn the whole retry budget."""
        from apkre.provider import McodeProvider, RunResult

        with tempfile.TemporaryDirectory() as d:
            wd = Path(d)
            p = McodeProvider(timeout=60, retries=5, backoff=0.01)
            strict_calls: list[bool] = []

            def fake(prompt, *, cwd, schema_file, last_message, attempt, use_schema):
                strict_calls.append(use_schema)
                if use_schema:
                    return RunResult(
                        ok=False,
                        error_code="STRUCTURED_OUTPUT_INVALID",
                        error_message="bad",
                        attempt=attempt,
                    )
                return RunResult(ok=True, output={"ok": True, "msg": "pong"})

            p.run_once = fake  # type: ignore[method-assign]
            res = p.run(
                "x",
                cwd=wd,
                schema_file=wd / "s.json",
                last_message=wd / "l.json",
                validate=lambda o: [],
                fallback_hint="Return the JSON object.",
            )
            self.assertTrue(res.ok)
            self.assertEqual(res.mode, "text-fallback")
            # Exactly one strict attempt, then straight to text mode.
            self.assertEqual(strict_calls, [True, False])

    def test_other_errors_still_retry(self) -> None:
        from apkre.provider import McodeProvider, RunResult

        with tempfile.TemporaryDirectory() as d:
            wd = Path(d)
            p = McodeProvider(timeout=60, retries=2, backoff=0.01)
            calls: list[int] = []

            def fake(prompt, *, cwd, schema_file, last_message, attempt, use_schema):
                calls.append(attempt)
                return RunResult(
                    ok=False, error_code="RATE_LIMIT", error_message="slow down"
                )

            p.run_once = fake  # type: ignore[method-assign]
            res = p.run(
                "x",
                cwd=wd,
                schema_file=wd / "s.json",
                last_message=wd / "l.json",
            )
            self.assertFalse(res.ok)
            self.assertEqual(calls, [1, 2, 3])


class TestProvider(unittest.TestCase):
    """Exercises the real mcode adapter, retries included."""

    TINY = {
        "type": "object",
        "properties": {"ok": {"type": "boolean"}, "msg": {"type": "string"}},
        "required": ["ok", "msg"],
        "additionalProperties": False,
    }

    def test_envelope_and_command_shape(self) -> None:
        import shutil

        from apkre.provider import McodeProvider

        if shutil.which("mcode") is None:
            self.skipTest("mcode not on PATH")
        p = McodeProvider(model=None, timeout=60)
        ok, note = p.available()
        self.assertTrue(ok, note)
        with tempfile.TemporaryDirectory() as d:
            wd = Path(d)
            cmd = p.build_command(
                "hello", cwd=wd, schema_file=wd / "s.json", last_message=wd / "l.json"
            )
            self.assertEqual(cmd[0], "mcode")
            self.assertEqual(cmd[1], "exec")
            self.assertIn("--output-schema", cmd)
            self.assertIn("--output-format", cmd)
            self.assertEqual(cmd[cmd.index("--output-format") + 1], "json")
            self.assertEqual(cmd[cmd.index("--cwd") + 1], str(wd))
            # One-shot: prompt always arrives on stdin, requested explicitly.
            # A bare positional "-" would be read as a literal dash and the
            # agent would run with an empty prompt.
            self.assertEqual(cmd[-2:], ["--input", "-"])
            self.assertNotIn("--continue", cmd)
            self.assertNotIn("--session", cmd)

    def test_structured_output_survives_retries(self) -> None:
        """Production path: strict first, text fallback if strict is rejected.

        The backend transiently rejects native strict output while plain text
        still works, so this asserts the caller always gets a valid object.
        """
        import shutil

        from apkre.provider import McodeProvider

        if shutil.which("mcode") is None:
            self.skipTest("mcode not on PATH")
        with tempfile.TemporaryDirectory() as d:
            wd = Path(d)
            sf = wd / "s.json"
            sf.write_text(json.dumps(self.TINY))
            lm = wd / "last.json"
            p = McodeProvider(timeout=180, retries=1, backoff=1.0)

            def check_tiny(obj: object) -> list[str]:
                if not isinstance(obj, dict):
                    return ["not an object"]
                return [k for k in ("ok", "msg") if k not in obj]

            res = p.run(
                "Respond with ONLY a JSON object: ok set to true, msg set to "
                "pong. No prose, no code fences.",
                cwd=wd,
                schema_file=sf,
                last_message=lm,
                validate=check_tiny,
                fallback_hint=(
                    'Return {"ok": <boolean>, "msg": <string>}. Nothing else.'
                ),
            )
            self.assertTrue(
                res.ok, f"attempt={res.attempt} mode={res.mode} "
                        f"code={res.error_code} msg={(res.error_message or '')[:200]}"
            )
            self.assertEqual(res.output, {"ok": True, "msg": "pong"})
            self.assertIn(res.mode, ("native-strict", "text-fallback"))
            self.assertIn("totalTokens", res.usage)

    def test_fallback_used_when_strict_rejected(self) -> None:
        """Force the strict path to fail and assert the fallback recovers."""
        from apkre.provider import McodeProvider, RunResult

        with tempfile.TemporaryDirectory() as d:
            wd = Path(d)
            sf = wd / "s.json"
            sf.write_text(json.dumps(self.TINY))
            p = McodeProvider(timeout=60, retries=0, backoff=0.01)

            def fake(prompt, *, cwd, schema_file, last_message, attempt, use_schema):
                if use_schema:
                    return RunResult(
                        ok=False,
                        error_code="STRUCTURED_OUTPUT_INVALID",
                        error_message="nope",
                        attempt=attempt,
                    )
                return RunResult(
                    ok=True,
                    output={"ok": True, "msg": "pong"},
                    attempt=attempt,
                    usage={"totalTokens": 5},
                )

            p.run_once = fake  # type: ignore[method-assign]
            res = p.run(
                "x",
                cwd=wd,
                schema_file=sf,
                last_message=wd / "l.json",
                validate=lambda o: [],
                fallback_hint="Return the JSON object.",
            )
            self.assertTrue(res.ok)
            self.assertEqual(res.mode, "text-fallback")
            self.assertEqual(res.output, {"ok": True, "msg": "pong"})
            self.assertEqual(p.fallbacks, 1)

    def test_no_fallback_when_strict_succeeds(self) -> None:
        from apkre.provider import McodeProvider, RunResult

        with tempfile.TemporaryDirectory() as d:
            wd = Path(d)
            p = McodeProvider(timeout=60, retries=0, backoff=0.01)
            calls: list[bool] = []

            def fake(prompt, *, cwd, schema_file, last_message, attempt, use_schema):
                calls.append(use_schema)
                return RunResult(ok=True, output={"ok": True, "msg": "pong"})

            p.run_once = fake  # type: ignore[method-assign]
            res = p.run(
                "x",
                cwd=wd,
                schema_file=wd / "s.json",
                last_message=wd / "l.json",
                fallback_hint="Return the JSON object.",
            )
            self.assertTrue(res.ok)
            self.assertEqual(res.mode, "native-strict")
            self.assertEqual(calls, [True])


if __name__ == "__main__":
    unittest.main()
