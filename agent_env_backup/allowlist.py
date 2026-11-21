"""Restore action allow-list.

Every step in RECONSTITUTE.yaml must be one of these actions. Anything else
is rejected before any restore work happens -- this is the only mechanism
that keeps a malicious or corrupted manifest from doing something the human
didn't agree to.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

ALLOWED_ACTIONS = {
    "verify_seed",
    "verify_checksums",
    "copy",
    "load",
    "smoke_check",
    "run",
}

# Actions that touch credentials or the network and therefore must be called
# out explicitly in the human-facing summary before any confirmation gate.
SENSITIVE_ACTIONS = {"run", "load"}


class AllowlistViolation(ValueError):
    pass


@dataclass
class Step:
    action: str
    description: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    touches_credentials: bool = False
    touches_network: bool = False

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Step":
        action = d.get("action")
        if action not in ALLOWED_ACTIONS:
            raise AllowlistViolation(
                f"step action {action!r} is not in the allow-list {sorted(ALLOWED_ACTIONS)}"
            )
        if action == "run":
            params = d.get("params", {})
            missing = [k for k in ("binary", "args", "timeout") if k not in params]
            if missing:
                raise AllowlistViolation(
                    f"'run' step missing required params {missing} "
                    "(run steps must specify explicit binary, args, and timeout)"
                )
        return cls(
            action=action,
            description=d.get("description", ""),
            params=d.get("params", {}),
            touches_credentials=bool(d.get("touches_credentials", False)),
            touches_network=bool(d.get("touches_network", False)),
        )


def validate_steps(raw_steps: List[Dict[str, Any]]) -> List[Step]:
    """Parse and validate every step against the allow-list.

    Raises AllowlistViolation on the first bad step, and raises before any
    step has been executed -- a manifest is validated as a whole up front.
    """
    return [Step.from_dict(s) for s in raw_steps]


def summarize_sensitive(steps: List[Step]) -> List[str]:
    """Human-facing lines calling out anything that touches credentials or
    the network, for display before the confirmation gate."""
    lines = []
    for s in steps:
        if s.action in SENSITIVE_ACTIONS or s.touches_credentials or s.touches_network:
            tags = []
            if s.touches_credentials:
                tags.append("CREDENTIALS")
            if s.touches_network:
                tags.append("NETWORK")
            if s.action == "run":
                tags.append("EXECUTES A BINARY")
            lines.append(f"[{'/'.join(tags) or s.action.upper()}] {s.description or s.action}")
    return lines
