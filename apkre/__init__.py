"""apkre — batch Android APK static analysis driven by the mcode CLI.

Each APK is staged into its own workspace containing only the target, a rizin
skill, a jadx MCP server, and an AGENTS.md task spec. A single one-shot
``mcode exec`` per APK then produces a schema-validated JSON finding set.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
