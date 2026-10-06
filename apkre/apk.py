"""APK discovery, hashing, safe unpacking and static inventory."""

from __future__ import annotations

import hashlib
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_SUFFIXES = (".apk",)
# Bundles that are APKs in disguise; each may hold several real APKs.
BUNDLE_SUFFIXES = (".xapk", ".apks", ".apkm")

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._+-]+")


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


@dataclass
class ApkFile:
    """One unit of work: a real APK on disk."""

    path: Path
    size: int
    sha256: str
    source_bundle: Path | None = None

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def stem(self) -> str:
        return self.path.stem


@dataclass
class BundleMember:
    inner_name: str
    data: bytes


def _iter_files(root: Path, suffixes: tuple[str, ...], recursive: bool) -> list[Path]:
    out: list[Path] = []
    if root.is_file():
        if root.suffix.lower() in suffixes:
            out.append(root)
        return out
    it = root.rglob("*") if recursive else root.glob("*")
    for p in it:
        if p.is_file() and p.suffix.lower() in suffixes:
            out.append(p)
    return sorted(out)


def discover(
    root: Path,
    suffixes: tuple[str, ...] = DEFAULT_SUFFIXES,
    recursive: bool = True,
    include_bundles: bool = True,
) -> list[ApkFile]:
    """Find APKs under *root*.

    When *include_bundles* is set, XAPK/APKS bundles are unpacked in memory and
    each contained ``*.apk`` is registered as its own work item.
    """
    root = Path(root).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"input path does not exist: {root}")

    all_suffixes = tuple(suffixes) + (BUNDLE_SUFFIXES if include_bundles else ())
    candidates = _iter_files(root, all_suffixes, recursive)

    found: list[ApkFile] = []
    for p in candidates:
        if p.suffix.lower() in (suffixes or DEFAULT_SUFFIXES):
            found.append(
                ApkFile(path=p, size=p.stat().st_size, sha256=sha256_file(p))
            )
        else:
            found.extend(_members_of_bundle(p))
    return found


def _members_of_bundle(bundle: Path) -> list[ApkFile]:
    out: list[ApkFile] = []
    try:
        with zipfile.ZipFile(bundle) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".apk"):
                    continue
                data = zf.read(info)
                out.append(
                    ApkFile(
                        path=bundle,
                        size=len(data),
                        sha256=hashlib.sha256(data).hexdigest(),
                        source_bundle=bundle,
                    )
                )
                # Keep the member payload so unpack() can materialise it.
                setattr(out[-1], "member", info.filename)
                setattr(out[-1], "member_data", data)
    except (zipfile.BadZipFile, OSError):
        return []
    return out


def _materialise(apk: ApkFile, dest: Path) -> Path:
    """Ensure a real file exists at *dest* for this work item."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = getattr(apk, "member_data", None)
    if data is not None:
        dest.write_bytes(data)
    else:
        dest = apk.path
    return dest


def safe_extract(zf: zipfile.ZipFile, dest: Path) -> list[str]:
    """Extract *zf* into *dest*, rejecting path traversal. Returns member names."""
    dest.mkdir(parents=True, exist_ok=True)
    dest_res = dest.resolve()
    written: list[str] = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        target = (dest_res / info.filename).resolve()
        if not str(target).startswith(str(dest_res)):
            continue  # zip-slip attempt
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, target.open("wb") as out:
            while True:
                block = src.read(1 << 20)
                if not block:
                    break
                out.write(block)
        written.append(info.filename)
    return written


@dataclass
class ApkInventory:
    """What is actually inside the archive - cheap, no agent tokens spent."""

    ok: bool
    entries: int = 0
    total_uncompressed: int = 0
    dex_files: list[str] = field(default_factory=list)
    native_libs: list[str] = field(default_factory=list)
    abis: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    suspicious_names: list[str] = field(default_factory=list)
    has_manifest: bool = False
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "entry_count": self.entries,
            "total_uncompressed_bytes": self.total_uncompressed,
            "dex_files": self.dex_files,
            "native_libs": self.native_libs,
            "abis": self.abis,
            "asset_count": len(self.assets),
            "signature_files": self.signatures,
            "suspicious_entries": self.suspicious_names,
            "has_manifest": self.has_manifest,
            "error": self.error,
        }


SUSPICIOUS_PATTERNS = (
    re.compile(r"lib/[\w-]+/(frida|xposed|substrate|magisk|liberty)", re.I),
    re.compile(r"(frida|hook|xposed|root|su$|magisk)", re.I),
    re.compile(r"\.(dex|so|jar)$", re.I),
    re.compile(r"assets/.*\.(js|py|sh|bin|dat)$", re.I),
)


def inventory(apk: ApkFile) -> ApkInventory:
    """List the archive contents without extracting anything."""
    inv = ApkInventory(ok=False)
    try:
        with zipfile.ZipFile(apk.path) as zf:
            names = zf.namelist()
            inv.entries = len(names)
            inv.has_manifest = "AndroidManifest.xml" in names
            for info in zf.infolist():
                inv.total_uncompressed += info.file_size
                n = info.filename
                if n.startswith("classes") and n.endswith(".dex"):
                    inv.dex_files.append(n)
                elif n.endswith(".so"):
                    inv.native_libs.append(n)
                    parts = n.split("/")
                    if len(parts) >= 3 and parts[1] not in inv.abis:
                        inv.abis.append(parts[1])
                elif n.startswith("assets/"):
                    inv.assets.append(n)
                elif n.startswith("META-INF/") and n.upper().endswith(
                    (".RSA", ".DSA", ".EC", ".SF", ".MF")
                ):
                    inv.signatures.append(n)
            inv.dex_files.sort()
            inv.native_libs.sort()
            inv.suspicious_names = sorted(
                {
                    n
                    for n in names
                    if any(p.search(n) for p in SUSPICIOUS_PATTERNS)
                }
            )[:80]
            inv.ok = inv.has_manifest
            if not inv.has_manifest:
                inv.error = "AndroidManifest.xml missing"
    except zipfile.BadZipFile as exc:
        inv.error = f"not a valid zip/apk: {exc}"
    except OSError as exc:
        inv.error = str(exc)
    return inv


def workdir_for(run_dir: Path, apk: ApkFile) -> Path:
    """Stable per-APK work directory name (safe, collision-resistant)."""
    label = _SAFE_NAME.sub("_", apk.stem)[:48]
    return run_dir / f"{label}-{apk.sha256[:12]}"
