"""RECONSTITUTE.yaml schema: build and parse the manifest written alongside
every backup payload.

This is the only file a restore needs to read to know what to do. It must be
self-contained enough that a cold agent with zero prior context about this
project can restore from it (see README.md "drop this prompt" snippet).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

MANIFEST_FILENAME = "RECONSTITUTE.yaml"
SCHEMA_VERSION = 1

DEFAULT_COACHING_TEMPLATE = (
    "Welcome back. I think we've got everything together, but some workflow "
    "may need a little jump-starting. All files saved on {saved_date} are "
    "present and verified."
)

DEFAULT_STEPS: List[Dict[str, Any]] = [
    {
        "action": "verify_seed",
        "description": "Confirm the seed phrase you were given matches this payload.",
    },
    {
        "action": "verify_checksums",
        "description": "Check every backed-up file against its recorded checksum.",
    },
    {
        "action": "copy",
        "description": "Copy the verified payload files to their restore destination.",
        "params": {},
    },
    {
        "action": "load",
        "description": "Load restored config/memory/notes into the running environment.",
        "params": {},
    },
    {
        "action": "smoke_check",
        "description": "Sanity-check that restored state looks usable "
        "(files present, non-empty, parseable).",
    },
]


@dataclass
class Manifest:
    schema_version: int
    created_at: str
    seed_fingerprint: str
    payload_hmac: str
    categories: List[str]
    include_paths: List[str]
    checksums: Dict[str, str]
    steps: List[Dict[str, Any]]
    coaching_template: str = DEFAULT_COACHING_TEMPLATE
    refresher_hint: Optional[str] = None
    tessera_object: Optional[Dict[str, Any]] = None  # {"object_id": ..., "uploaded": bool, "destination": ...}
    notes: str = ""
    source_host: str = ""

    def to_yaml(self) -> str:
        return yaml.safe_dump(asdict(self), sort_keys=False, default_flow_style=False)

    @classmethod
    def from_yaml(cls, text: str) -> "Manifest":
        d = yaml.safe_load(text)
        if not isinstance(d, dict):
            raise ValueError("RECONSTITUTE.yaml did not parse to a mapping")
        known_fields = {f for f in cls.__dataclass_fields__}
        filtered = {k: v for k, v in d.items() if k in known_fields}
        missing = known_fields - filtered.keys() - {
            f for f, fld in cls.__dataclass_fields__.items()
            if fld.default is not None or fld.default_factory is not None  # type: ignore[attr-defined]
        }
        # required fields with no default
        required = {"schema_version", "created_at", "seed_fingerprint", "payload_hmac",
                    "categories", "include_paths", "checksums", "steps"}
        missing_required = required - filtered.keys()
        if missing_required:
            raise ValueError(f"RECONSTITUTE.yaml missing required fields: {sorted(missing_required)}")
        return cls(**filtered)

    def coaching_message(self) -> str:
        saved_date = self.created_at.split("T")[0] if "T" in self.created_at else self.created_at
        return self.coaching_template.format(saved_date=saved_date)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_manifest(
    seed_fingerprint: str,
    payload_hmac: str,
    categories: List[str],
    include_paths: List[str],
    checksums: Dict[str, str],
    tessera_object: Optional[Dict[str, Any]] = None,
    refresher_hint: Optional[str] = None,
    notes: str = "",
    source_host: str = "",
) -> Manifest:
    return Manifest(
        schema_version=SCHEMA_VERSION,
        created_at=now_iso(),
        seed_fingerprint=seed_fingerprint,
        payload_hmac=payload_hmac,
        categories=categories,
        include_paths=include_paths,
        checksums=checksums,
        steps=list(DEFAULT_STEPS),
        refresher_hint=refresher_hint,
        tessera_object=tessera_object,
        notes=notes,
        source_host=source_host,
    )
