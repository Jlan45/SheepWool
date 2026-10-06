"""Adapter for the ``mcode`` CLI (MiniMax Code), driven in one-shot mode.

One APK == one ``mcode exec`` process. No session reuse, no TUI, no
interactive permission prompts: the run is schema-constrained and the result is
read straight out of the ``exec.result`` envelope.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_BINARY = os.environ.get("APKRE_MCODE_BIN", "mcode")

# Errors the CLI marks retryable; worth another attempt.
RETRYABLE_CODES = {
    "STRUCTURED_OUTPUT_INVALID",
    "RUNTIME",
    "RATE_LIMIT",
    "TIMEOUT",
    "OVERLOADED",
    "INTERNAL",
}


@dataclass
class RunResult:
    ok: bool
    output: dict[str, Any] | None = None
    raw: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    attempt: int = 1
    duration_ms: int = 0
    usage: dict[str, int] = field(default_factory=dict)
    model: dict[str, Any] = field(default_factory=dict)
    run_id: str | None = None
    session_id: str | None = None
    validation_errors: list[str] = field(default_factory=list)
    mode: str = "native-strict"


class McodeProvider:
    """Runs one analysis task per APK via ``mcode exec``."""

    name = "mcode"

    def __init__(
        self,
        *,
        binary: str = DEFAULT_BINARY,
        model: str | None = None,
        effort: str | None = None,
        max_steps: int | None = None,
        timeout: int = 900,
        permission: str = "full",
        prompt_mode: str = "work",
        retries: int = 2,
        backoff: float = 3.0,
        extra_args: list[str] | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.binary = binary
        self.model = model
        self.effort = effort
        self.max_steps = max_steps
        self.timeout = timeout
        self.permission = permission
        self.prompt_mode = prompt_mode
        self.retries = retries
        self.backoff = backoff
        self.extra_args = extra_args or []
        self.env = env
        self._fallbacks = 0

    @property
    def fallbacks(self) -> int:
        """How many runs had to fall back from native strict output."""
        return self._fallbacks

    # -- availability -------------------------------------------------------

    def available(self) -> tuple[bool, str]:
        path = shutil.which(self.binary)
        if not path:
            return False, f"{self.binary} not found on PATH"
        return True, path

    # -- command construction ---------------------------------------------

    def build_command(
        self,
        prompt: str,
        *,
        cwd: Path,
        schema_file: Path,
        last_message: Path,
        use_schema: bool = True,
    ) -> list[str]:
        cmd = [
            self.binary,
            "exec",
            "--cwd",
            str(cwd),
            "--permission",
            self.permission,
            "--prompt-mode",
            self.prompt_mode,
            "--output-format",
            "json",
        ]
        if use_schema:
            cmd += ["--output-schema", str(schema_file)]
        cmd += [
            "-o",
            str(last_message),
            "--timeout",
            f"{self.timeout}s",
        ]
        if self.model:
            cmd += ["--model", self.model]
        if self.effort:
            cmd += ["--effort", self.effort]
        if self.max_steps:
            cmd += ["--max-steps", str(self.max_steps)]
        cmd += self.extra_args
        # NOTE: a bare positional "-" is NOT stdin; mcode reads it as a literal
        # dash and runs with an empty prompt. Stdin must be requested explicitly.
        cmd += ["--input", "-"]
        return cmd

    # -- execution ----------------------------------------------------------

    def run_once(
        self,
        prompt: str,
        *,
        cwd: Path,
        schema_file: Path,
        last_message: Path,
        attempt: int = 1,
        use_schema: bool = True,
    ) -> RunResult:
        cmd = self.build_command(
            prompt,
            cwd=cwd,
            schema_file=schema_file,
            last_message=last_message,
            use_schema=use_schema,
        )
        env = {**os.environ, **(self.env or {})}
        try:
            proc = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                cwd=str(cwd),
                timeout=self.timeout + 120,
                env=env,
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            return RunResult(
                ok=False,
                error_code="TIMEOUT",
                error_message=f"mcode exec exceeded {self.timeout}s",
                attempt=attempt,
            )
        except OSError as exc:
            return RunResult(
                ok=False, error_code="SPAWN", error_message=str(exc), attempt=attempt
            )

        return self._parse(proc.stdout, proc.stderr, proc.returncode, attempt, last_message)

    def _parse(
        self,
        stdout: str,
        stderr: str,
        returncode: int,
        attempt: int,
        last_message: Path,
    ) -> RunResult:
        envelope = _extract_envelope(stdout)

        if envelope is None:
            return RunResult(
                ok=False,
                raw=stdout[-4000:] or None,
                error_code="NO_ENVELOPE",
                error_message=(stderr.strip() or stdout.strip() or "no output")[-600:],
                attempt=attempt,
            )

        status = envelope.get("status", "failed")
        usage = envelope.get("usage") or {}
        model = envelope.get("model") or {}

        if status == "succeeded":
            payload = envelope.get("output")
            # Native strict mode yields an object; text mode yields a string.
            if isinstance(payload, str):
                payload = extract_json(payload)
            if isinstance(payload, dict):
                return RunResult(
                    ok=True,
                    output=payload,
                    raw=stdout[-4000:],
                    duration_ms=int(envelope.get("durationMs") or 0),
                    usage={k: v for k, v in usage.items() if isinstance(v, int)},
                    model=model,
                    run_id=envelope.get("runId"),
                    session_id=envelope.get("sessionId"),
                    attempt=attempt,
                )

        err = envelope.get("error") or {}
        code = err.get("code") or ("EXIT" if returncode else "UNKNOWN")
        message = err.get("message") or (stderr.strip()[-600:] if stderr else "")

        # Envelope said failure but the final message file may still hold a
        # usable object (e.g. output written before a post-processing error).
        salvaged = _read_json_file(last_message)
        if salvaged and code == "STRUCTURED_OUTPUT_INVALID":
            return RunResult(
                ok=True,
                output=salvaged,
                raw=stdout[-4000:],
                error_code=code,
                error_message=message,
                attempt=attempt,
                duration_ms=int(envelope.get("durationMs") or 0),
                usage={k: v for k, v in usage.items() if isinstance(v, int)},
                model=model,
                run_id=envelope.get("runId"),
                session_id=envelope.get("sessionId"),
            )

        return RunResult(
            ok=False,
            raw=stdout[-4000:],
            error_code=code,
            error_message=message,
            attempt=attempt,
            duration_ms=int(envelope.get("durationMs") or 0),
            usage={k: v for k, v in usage.items() if isinstance(v, int)},
            model=model,
            run_id=envelope.get("runId"),
            session_id=envelope.get("sessionId"),
        )

    def is_retryable(self, result: RunResult) -> bool:
        if result.error_code in RETRYABLE_CODES:
            return True
        return result.error_code in (None, "UNKNOWN", "NO_ENVELOPE", "EXIT")

    def run(
        self,
        prompt: str,
        *,
        cwd: Path,
        schema_file: Path,
        last_message: Path,
        validate=None,
        fallback_hint: str | None = None,
    ) -> RunResult:
        """Run to completion, degrading gracefully if strict output is broken.

        Phase 1 uses ``--output-schema`` (native strict). If the backend keeps
        rejecting that — which it does transiently, while plain text replies
        still work — phase 2 drops the schema, describes the contract inline,
        and extracts the JSON ourselves. Either way the caller gets a validated
        object, not a parsing problem.
        """
        result = self._attempt_loop(
            prompt,
            cwd=cwd,
            schema_file=schema_file,
            last_message=last_message,
            validate=validate,
            use_schema=True,
        )
        if result.ok or fallback_hint is None:
            return result

        self._fallbacks += 1
        text_prompt = (
            prompt
            + "\n\n"
            + fallback_hint
            + "\n\nIMPORTANT: output the JSON object and nothing else. The first "
            "character of your reply must be { and the last must be }. No "
            "markdown, no code fences, no explanation."
        )
        fallback = self._attempt_loop(
            text_prompt,
            cwd=cwd,
            schema_file=schema_file,
            last_message=last_message,
            validate=validate,
            use_schema=False,
        )
        # Report the path actually taken, success or not.
        fallback.mode = "text-fallback"
        return fallback

    def _attempt_loop(
        self,
        prompt: str,
        *,
        cwd: Path,
        schema_file: Path,
        last_message: Path,
        validate,
        use_schema: bool,
    ) -> RunResult:
        attempt = 0
        result = RunResult(ok=False, error_code="NOT_RUN")
        current_prompt = prompt

        while attempt <= self.retries:
            attempt += 1
            result = self.run_once(
                current_prompt,
                cwd=cwd,
                schema_file=schema_file,
                last_message=last_message,
                attempt=attempt,
                use_schema=use_schema,
            )
            if result.ok and validate is not None and result.output is not None:
                problems = validate(result.output)
                if problems:
                    result.validation_errors = problems
                    result.ok = False
                    result.error_code = "SCHEMA_VALIDATION"
                    result.error_message = "; ".join(problems[:5])

            if result.ok:
                return result
            # Retrying the same schema against native strict output rarely
            # helps, and each attempt can cost minutes on a real analysis. Fall
            # through to the caller's text-mode fallback instead.
            if result.error_code == "STRUCTURED_OUTPUT_INVALID":
                return result
            if attempt > self.retries or not self.is_retryable(result):
                return result

            delay = self.backoff * (2 ** (attempt - 1))
            time.sleep(min(delay, 30.0))
            # Tighten the contract on each retry; the most common failure is
            # prose or a fenced block instead of a bare JSON object.
            current_prompt = (
                prompt
                + "\n\nIMPORTANT: your previous reply was rejected. Reply with the "
                "JSON object ONLY. The first character of your reply must be { and "
                "the last must be }. No markdown, no code fences, no commentary."
            )
        return result


def extract_json(text: str) -> dict | None:
    """Pull the first complete JSON object out of a free-text reply.

    Handles fenced code blocks and leading/trailing prose by scanning for a
    balanced ``{...}`` span rather than trusting the whole string.
    """
    if not text:
        return None
    stripped = text.strip()
    for candidate in (stripped, _unfence(stripped)):
        obj = _try_json(candidate)
        if obj is not None:
            return obj
    return _scan_balanced(stripped)


def _unfence(text: str) -> str:
    if not text.startswith("```"):
        return text
    body = text[3:]
    if "\n" in body:
        first, rest = body.split("\n", 1)
        if first.strip().lower() in ("json", "javascript", "js", ""):
            body = rest
    if body.rstrip().endswith("```"):
        body = body.rstrip()[:-3]
    return body.strip()


def _try_json(text: str) -> dict | None:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def _scan_balanced(text: str) -> dict | None:
    """Find the first brace-balanced object, ignoring braces inside strings."""
    start = text.find("{")
    while start != -1:
        depth = 0
        in_str = False
        escaped = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    obj = _try_json(text[start : i + 1])
                    if obj is not None:
                        return obj
                    break
        start = text.find("{", start + 1)
    return None


def _extract_envelope(stdout: str) -> dict | None:
    """Pull the ``exec.result`` object out of mcode stdout."""
    if not stdout:
        return None
    text = stdout.strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    # Fall back to the last complete JSON object in the stream.
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("type") == "exec.result":
            return obj
        if isinstance(obj, dict) and "status" in obj:
            return obj
    return None


def _read_json_file(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data, dict):
        return data
    # The file may hold a JSON string wrapping the object.
    if isinstance(data, str):
        try:
            inner = json.loads(data)
        except json.JSONDecodeError:
            return None
        if isinstance(inner, dict):
            return inner
    return None
