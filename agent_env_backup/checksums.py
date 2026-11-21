"""Checksumming helpers for included paths."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def walk_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        # never descend into VCS internals or obvious junk by default
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__", ".DS_Store")]
        for fn in filenames:
            yield Path(dirpath) / fn


def checksum_tree(paths: List[str]) -> Dict[str, str]:
    """Return {relative-or-absolute path string: sha256 hex} for every file
    under the given include paths."""
    out: Dict[str, str] = {}
    for p in paths:
        root = Path(p).expanduser()
        if not root.exists():
            continue
        for f in walk_files(root):
            out[str(f)] = sha256_file(f)
    return out


def verify_checksums(checksums: Dict[str, str], base: Path) -> Tuple[List[str], List[str]]:
    """Verify files extracted under `base` match recorded checksums.

    Returns (ok_paths, bad_or_missing_paths).
    """
    ok, bad = [], []
    for relpath, expected in checksums.items():
        full = base / relpath
        if not full.exists():
            bad.append(relpath)
            continue
        actual = sha256_file(full)
        if actual == expected:
            ok.append(relpath)
        else:
            bad.append(relpath)
    return ok, bad
