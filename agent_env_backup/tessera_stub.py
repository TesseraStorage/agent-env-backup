"""Optional Tessera destination -- STUB for this release.

Per the buildout packet for this pass: this module documents the intended
integration and computes the object name/identifiers deterministically, but
does NOT make any real network or tessera-cli calls yet. Wiring a real
upload/download is explicit future work (see README "Known limitations").

Design (for the real implementation, later):
  - Treat the backup payload as an ORDINARY client object on the existing
    `per_action` billing rail -- no privileged paths, no special metadata,
    no new billing exceptions.
  - Upload is one-way (local -> Tessera). No automatic two-way sync.
  - The object name is derived from the seed so restore can look it up
    without storing the seed anywhere server-side:
      object_name = sha256("agent-env-backup:tessera-object:" + seed)[:32]
  - Expected real calls would be something like:
      tessera-cli upload --file <payload.tar.gz> --name <object_name>
      tessera-cli download --name <object_name> --out <dest>
    via subprocess, through the same allow-listed `run` action restore
    already supports -- never a bespoke client.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional


@dataclass
class TesseraObjectPlan:
    object_name: str
    would_upload: bool
    note: str


def plan_tessera_object(seed: str, upload_requested: bool) -> Optional[TesseraObjectPlan]:
    """Compute what the Tessera object WOULD be named, without doing anything.

    Returns None if the human didn't ask for a Tessera destination at all.
    """
    if not upload_requested:
        return None
    object_name = hashlib.sha256(
        f"agent-env-backup:tessera-object:{seed.strip().lower()}".encode()
    ).hexdigest()[:32]
    return TesseraObjectPlan(
        object_name=object_name,
        would_upload=False,
        note=(
            "STUB: no real upload was performed in this release. "
            "Real upload would run `tessera-cli` as an ordinary client object "
            "on the per_action rail -- see module docstring."
        ),
    )


def stub_download_notice(object_name: str) -> str:
    return (
        f"STUB: restore wanted to fall back to Tessera object '{object_name}', "
        "but no real download is implemented in this release. "
        "Use the local payload, or implement the real tessera-cli call "
        "documented in agent_env_backup/tessera_stub.py."
    )
