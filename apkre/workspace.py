"""Build a self-contained per-APK analysis workspace.

Layout produced (nothing else):

    <workdir>/
      .agents/
        rizin-re/
          SKILL.md      # the rizin playbook the agent reads
      .mcp.json         # jadx MCP server, stdio transport
      AGENTS.md         # the full task flow
      <apk>             # the target

No pre-extraction, no pre-parsing: the agent does the analysis itself through
the two injected tools. The orchestrator only stages files.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

TEMPLATES = Path(__file__).parent / "templates"

MCP_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"

AGENTS_TEMPLATE = TEMPLATES / "AGENTS.md"
SKILL_TEMPLATE = TEMPLATES / "skill-rizin.md"


def _human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} GB"


@dataclass
class Workspace:
    root: Path
    apk_path: Path          # the APK as it appears inside the workspace
    skill_dir: Path
    mcp_config: Path
    agents_md: Path

    def describe(self) -> dict:
        return {
            "root": str(self.root),
            "apk": str(self.apk_path),
            "skill": str(self.skill_dir),
            "mcp_config": str(self.mcp_config),
            "agents_md": str(self.agents_md),
        }


def resolve_jadx_command() -> tuple[str | None, str]:
    """Locate the jadx MCP executable. Returns (command, note)."""
    override = os.environ.get("APKRE_JADX_MCP_BIN")
    if override:
        return override, "from APKRE_JADX_MCP_BIN"
    found = shutil.which("jadx-headless-mcp")
    if found:
        return found, "resolved from PATH"
    return None, (
        "jadx-headless-mcp not found. Install with: "
        "npm install -g jadx-headless-mcp@0.7.0"
    )


def _stage_apk(src: Path, dest: Path, materialize: bool) -> None:
    if materialize or src.stat().st_size < 0:  # always copy when asked
        shutil.copy2(src, dest)
        return
    try:
        dest.symlink_to(src.resolve())
    except OSError:
        shutil.copy2(src, dest)


def build_workspace(
    workdir: Path,
    apk_path: Path,
    apk_name: str,
    apk_sha256: str,
    apk_size: int,
    *,
    jadx_command: str | None,
    java_bin: str | None = None,
    materialize: bool = False,
    autoload: bool = True,
) -> Workspace:
    """Create/refresh the workspace and return its layout."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    # 1. the APK
    staged = workdir / apk_name
    if staged.exists() or staged.is_symlink():
        staged.unlink()
    _stage_apk(Path(apk_path), staged, materialize)

    # 2. the skill
    skill_dir = workdir / ".agents" / "rizin-re"
    skill_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SKILL_TEMPLATE, skill_dir / "SKILL.md")

    # 3. the MCP server (stdio)
    servers: dict = {}
    if jadx_command:
        args = ["serve"]
        if autoload:
            # Point at the workspace copy, not the symlink target, so the
            # workspace stays self-describing if it is moved.
            args += ["--apk", str(staged)]
        entry: dict = {
            "type": "stdio",
            "command": jadx_command,
            "args": args,
            "description": "Headless JADX decompiler: classes, methods, smali, resources, xrefs.",
        }
        env: dict[str, str] = {}
        if java_bin:
            env["JADX_MCP_JAVA"] = java_bin
        if env:
            entry["env"] = env
        servers["jadx"] = entry

    mcp_config = workdir / ".mcp.json"
    mcp_config.write_text(
        json.dumps(
            {"$schema": MCP_SCHEMA, "mcpServers": servers}, indent=2
        )
        + "\n",
        encoding="utf-8",
    )

    # 4. the task flow
    agents_md = workdir / "AGENTS.md"
    agents_md.write_text(
        AGENTS_TEMPLATE.read_text(encoding="utf-8")
        .replace("{{APK_NAME}}", apk_name)
        .replace("{{APK_SHA256}}", apk_sha256)
        .replace("{{APK_SIZE}}", f"{apk_size} ({_human(apk_size)})"),
        encoding="utf-8",
    )

    return Workspace(
        root=workdir,
        apk_path=staged,
        skill_dir=skill_dir,
        mcp_config=mcp_config,
        agents_md=agents_md,
    )
