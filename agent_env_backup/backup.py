"""Backup creation: category suggestion, human confirmation, ENCRYPTED write.

Nothing is written to disk unencrypted. The plaintext tar exists only in
memory; the on-disk artifact is payload.tar.gz.enc (AES-256-GCM, key derived
from the human's seed via scrypt).
"""
from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import crypto, manifest as manifest_mod
from .checksums import checksum_tree
from .seed import generate_seed, payload_hmac, seed_fingerprint
from .tessera_stub import plan_tessera_object

PAYLOAD_FILENAME = "payload.tar.gz.enc"

# Suggested category -> example default paths. These are SUGGESTIONS only;
# the human picks/edits the real include list interactively (or via --include).
SUGGESTED_CATEGORIES: Dict[str, List[str]] = {
    "config": ["~/.config"],
    "memory_notes": ["~/.hermes/profiles"],
    "handoffs": [],
    "cli_state": ["~/.cache"],
    "credentials_explicit_approval_required": [],
}


def suggest_categories() -> Dict[str, List[str]]:
    """Return the category suggestions. Caller is responsible for presenting
    these to the human and getting back an explicit, possibly-edited list --
    this function never reads the filesystem or decides anything on its own.
    """
    return {k: list(v) for k, v in SUGGESTED_CATEGORIES.items()}


def build_payload_tar(include_paths: List[str]) -> bytes:
    """Build an in-memory tar.gz of every existing path in include_paths.

    The returned bytes are plaintext and MUST only live in memory -- the
    caller encrypts before any disk write.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in include_paths:
            full = Path(p).expanduser()
            if full.exists():
                tar.add(full, arcname=str(full))
    return buf.getvalue()


def create_backup(
    include_paths: List[str],
    categories: List[str],
    dest_dir: Path,
    upload_to_tessera: bool = False,
    notes: str = "",
    source_host: str = "",
    refresher_hint: Optional[str] = None,
) -> Tuple[str, Path]:
    """Write a local ENCRYPTED backup payload + RECONSTITUTE.yaml under dest_dir.

    Returns (seed_phrase, backup_dir). Caller must have already shown the
    include list to the human and gotten explicit OK -- this function does
    not prompt; see cli.py for the interactive confirmation gate.

    The seed is shown to the human exactly once (by the CLI) and is never
    written anywhere by this tool.
    """
    seed = generate_seed()
    fp = seed_fingerprint(seed)

    plaintext = build_payload_tar(include_paths)
    checksums = checksum_tree(include_paths)  # computed pre-encryption
    blob = crypto.encrypt(seed, plaintext)
    del plaintext  # best-effort: drop the only cleartext copy promptly
    hmac_hex = payload_hmac(seed, blob)  # seed-bound integrity over the encrypted blob

    tplan = plan_tessera_object(seed, upload_to_tessera)
    tessera_object = None
    if tplan is not None:
        tessera_object = {
            "object_id": tplan.object_name,
            "uploaded": tplan.would_upload,
            "destination": "tessera",
            "note": tplan.note,
        }

    backup_dir = dest_dir.expanduser() / f"agent-env-backup-{fp}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    payload_path = backup_dir / PAYLOAD_FILENAME
    payload_path.write_bytes(blob)

    m = manifest_mod.build_manifest(
        seed_fingerprint=fp,
        payload_hmac=hmac_hex,
        categories=categories,
        include_paths=include_paths,
        checksums=checksums,
        tessera_object=tessera_object,
        refresher_hint=refresher_hint,
        notes=notes,
        source_host=source_host,
    )
    manifest_path = backup_dir / manifest_mod.MANIFEST_FILENAME
    manifest_path.write_text(m.to_yaml())

    return seed, backup_dir
