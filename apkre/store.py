"""Content-addressed run state (SQLite) so batches can resume.

Keyed by APK sha256: re-running against the same corpus skips work that already
succeeded, even if the files were moved or renamed.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    sha256        TEXT PRIMARY KEY,
    apk_path      TEXT,
    name          TEXT,
    size          INTEGER,
    status        TEXT NOT NULL DEFAULT 'pending',
    attempt       INTEGER DEFAULT 0,
    provider      TEXT,
    model         TEXT,
    package_name  TEXT,
    risk_score    INTEGER,
    risk_level    TEXT,
    input_tokens  INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    total_tokens  INTEGER DEFAULT 0,
    duration_ms   INTEGER DEFAULT 0,
    error_code    TEXT,
    error_message TEXT,
    started_at    REAL,
    finished_at   REAL,
    report_path   TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


class Store:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- registration -------------------------------------------------------

    def register(self, items: Iterable[Any]) -> None:
        rows = [
            (
                it.sha256,
                str(it.path),
                it.name,
                it.size,
                "pending",
            )
            for it in items
        ]
        self.conn.executemany(
            "INSERT INTO runs (sha256, apk_path, name, size, status) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(sha256) DO UPDATE SET apk_path=excluded.apk_path, name=excluded.name",
            rows,
        )
        self.conn.commit()

    def known_sha(self) -> set[str]:
        return {r["sha256"] for r in self.conn.execute("SELECT sha256 FROM runs")}

    def status_of(self, sha: str) -> str | None:
        row = self.conn.execute(
            "SELECT status FROM runs WHERE sha256=?", (sha,)
        ).fetchone()
        return row["status"] if row else None

    def succeeded_shas(self) -> set[str]:
        return {
            r["sha256"]
            for r in self.conn.execute(
                "SELECT sha256 FROM runs WHERE status='succeeded'"
            )
        }

    # -- lifecycle ----------------------------------------------------------

    def mark_running(self, sha: str, provider: str, model: str | None) -> None:
        self.conn.execute(
            "UPDATE runs SET status='running', provider=?, model=?, started_at=?, "
            "attempt=COALESCE(attempt,0)+1 WHERE sha256=?",
            (provider, model, time.time(), sha),
        )
        self.conn.commit()

    def mark_reset(self, sha: str) -> None:
        self.conn.execute(
            "UPDATE runs SET status='pending', error_code=NULL, error_message=NULL, "
            "started_at=NULL WHERE sha256=?",
            (sha,),
        )
        self.conn.commit()

    def mark_succeeded(
        self,
        sha: str,
        *,
        output: dict,
        usage: dict,
        duration_ms: int,
        provider: str,
        model: str | None,
        report_path: str | None,
    ) -> None:
        self.conn.execute(
            "UPDATE runs SET status='succeeded', finished_at=?, risk_score=?, "
            "risk_level=?, package_name=?, input_tokens=?, output_tokens=?, "
            "total_tokens=?, duration_ms=?, error_code=NULL, error_message=NULL, "
            "provider=?, model=?, report_path=? WHERE sha256=?",
            (
                time.time(),
                output.get("risk_score"),
                output.get("risk_level"),
                output.get("package_name"),
                int(usage.get("inputTokens") or 0),
                int(usage.get("outputTokens") or 0),
                int(usage.get("totalTokens") or 0),
                duration_ms,
                provider,
                model,
                report_path,
                sha,
            ),
        )
        self.conn.commit()

    def mark_failed(
        self, sha: str, *, code: str | None, message: str | None, duration_ms: int
    ) -> None:
        self.conn.execute(
            "UPDATE runs SET status='failed', finished_at=?, error_code=?, "
            "error_message=?, duration_ms=? WHERE sha256=?",
            (time.time(), code, (message or "")[:2000], duration_ms, sha),
        )
        self.conn.commit()

    # -- queries ------------------------------------------------------------

    def all_rows(self) -> list[sqlite3.Row]:
        return list(
            self.conn.execute("SELECT * FROM runs ORDER BY risk_score DESC, name")
        )

    def counts(self) -> dict[str, int]:
        return {
            r["status"]: r["n"]
            for r in self.conn.execute(
                "SELECT status, COUNT(*) AS n FROM runs GROUP BY status"
            )
        }

    def token_totals(self) -> dict[str, int]:
        row = self.conn.execute(
            "SELECT COALESCE(SUM(input_tokens),0) i, COALESCE(SUM(output_tokens),0) o, "
            "COALESCE(SUM(total_tokens),0) t, COALESCE(SUM(duration_ms),0) d FROM runs"
        ).fetchone()
        return {
            "input_tokens": row["i"],
            "output_tokens": row["o"],
            "total_tokens": row["t"],
            "duration_ms": row["d"],
        }

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO meta (key,value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)),
        )
        self.conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError:
            return default
