"""Restore / reconstitution.

Flow (every mutating step gated on an explicit human confirmation):

  1. Locate backup dir (explicit --path, or scan a directory for
     agent-env-backup-<seed_fingerprint>).
  2. Parse RECONSTITUTE.yaml and validate EVERY step against the action
     allow-list before anything runs.
  3. Human supplies the seed. Without it nothing is decrypted, ever.
  4. verify_seed: wordlist checksum + manifest fingerprint match +
     seed-bound HMAC over the encrypted blob (no decryption needed).
  5. Human-facing summary: all steps, with credential/network/run steps
     explicitly flagged, then a confirmation gate.
  6. Steps run in order, each behind its own gate. Decryption happens in
     memory only; files hit disk only at the `copy` step. Existing files at
     the destination are renamed to *.pre-restore-<ts> first (conservation
     bias: prefer keeping data, flag anything destructive).

Dry-run mode performs steps 1-5 plus in-memory verification only -- it never
writes, and decrypts only if the human explicitly authorizes it.
"""
from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from . import crypto, manifest as manifest_mod
from .allowlist import Step, summarize_sensitive, validate_steps
from .backup import PAYLOAD_FILENAME
from .checksums import sha256_file
from .seed import payload_hmac, seed_fingerprint, verify_seed
from .tessera_stub import stub_download_notice


class RestoreError(RuntimeError):
    pass


@dataclass
class LocatedBackup:
    backup_dir: Path
    manifest: manifest_mod.Manifest
    payload_path: Path


def locate_backup(seed: str, path: Optional[Path], search_dir: Path) -> LocatedBackup:
    fp = seed_fingerprint(seed)
    candidates: List[Path] = []
    if path is not None:
        p = path.expanduser()
        # accept either the backup dir itself or a parent containing it
        if (p / manifest_mod.MANIFEST_FILENAME).exists():
            candidates.append(p)
        elif (p / f"agent-env-backup-{fp}").exists():
            candidates.append(p / f"agent-env-backup-{fp}")
    else:
        for d in sorted(search_dir.expanduser().glob(f"agent-env-backup-{fp}*")):
            candidates.append(d)

    for c in candidates:
        mpath = c / manifest_mod.MANIFEST_FILENAME
        ppath = c / PAYLOAD_FILENAME
        if mpath.exists() and ppath.exists():
            m = manifest_mod.Manifest.from_yaml(mpath.read_text())
            return LocatedBackup(backup_dir=c, manifest=m, payload_path=ppath)

    searched = str(path) if path else str(search_dir)
    raise RestoreError(
        f"no valid backup for this seed (fingerprint {fp}) found under {searched}. "
        + (
            stub_download_notice(fp)
            if path is None
            else "Check the path and try again."
        )
    )


def verify_seed_against_manifest(seed: str, lb: LocatedBackup) -> None:
    """Seed integrity gate. Raises RestoreError on any mismatch.

    Checks, in order: wordlist checksum, manifest fingerprint, seed-bound
    HMAC over the encrypted payload. None of these require decryption.
    """
    if not verify_seed(seed):
        raise RestoreError("seed phrase failed its built-in checksum (typo?)")
    fp = seed_fingerprint(seed)
    if fp != lb.manifest.seed_fingerprint:
        raise RestoreError(
            f"seed fingerprint {fp} does not match manifest "
            f"{lb.manifest.seed_fingerprint} -- wrong seed for this backup"
        )
    blob = lb.payload_path.read_bytes()
    actual = payload_hmac(seed, blob)
    if actual != lb.manifest.payload_hmac:
        raise RestoreError(
            "seed-bound payload HMAC mismatch -- the payload file does not "
            "belong to this seed (corrupted or swapped archive)"
        )


def decrypt_payload(seed: str, lb: LocatedBackup) -> bytes:
    """Decrypt the payload in memory. Only ever called after the human has
    supplied the seed and passed verify_seed_against_manifest."""
    try:
        return crypto.decrypt(seed, lb.payload_path.read_bytes())
    except crypto.DecryptionError as e:
        raise RestoreError(str(e)) from None


def verify_checksums_in_memory(tar_bytes: bytes, m: manifest_mod.Manifest) -> Tuple[List[str], List[str]]:
    """Check every tar member against the manifest checksums without writing
    anything to disk. Returns (ok, bad_or_missing)."""
    ok, bad = [], []
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            name = member.name.lstrip("/")
            seen.add(name)
            data = tar.extractfile(member).read()
            digest = hashlib.sha256(data).hexdigest()
            # manifest keys are the absolute path strings recorded at backup time
            expected = m.checksums.get("/" + name, m.checksums.get(name))
            if expected is not None and expected == digest:
                ok.append(name)
            else:
                bad.append(name)
    recorded = {k.lstrip("/") for k in m.checksums}
    missing = recorded - seen
    return ok, bad + sorted(missing)


def plan_steps(m: manifest_mod.Manifest) -> List[Step]:
    """Validate the manifest's steps against the allow-list, up front."""
    return validate_steps(m.steps)


def human_summary(m: manifest_mod.Manifest, steps: List[Step]) -> str:
    lines = [
        "=== Restore plan ===",
        f"Backup created : {m.created_at}",
        f"Categories     : {', '.join(m.categories) or '(none recorded)'}",
        f"Files recorded : {len(m.checksums)}",
        f"Steps ({len(steps)}):",
    ]
    for i, s in enumerate(steps, 1):
        lines.append(f"  {i}. [{s.action}] {s.description}")
    sensitive = summarize_sensitive(steps)
    if sensitive:
        lines.append("")
        lines.append("!! The following steps touch credentials, the network, or execute a binary:")
        lines.extend("   " + s for s in sensitive)
    else:
        lines.append("No step touches credentials, the network, or executes a binary.")
    return "\n".join(lines)


def execute_steps(
    steps: List[Step],
    m: manifest_mod.Manifest,
    tar_bytes: bytes,
    dest_override: Optional[Path],
    confirm: Callable[[str], bool],
    dry_run: bool = False,
) -> List[str]:
    """Run the allow-listed steps in order. `confirm(prompt)` must return
    True before any mutating step executes. Returns a log of what happened."""
    log: List[str] = []
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    for i, step in enumerate(steps, 1):
        label = f"step {i}/{len(steps)} [{step.action}] {step.description}"

        if step.action == "verify_seed":
            log.append(f"OK   {label} (already passed before decryption)")
            continue

        if step.action == "verify_checksums":
            ok, bad = verify_checksums_in_memory(tar_bytes, m)
            if bad:
                raise RestoreError(
                    f"{label}: {len(bad)} file(s) failed checksum or are missing: "
                    + ", ".join(bad[:10])
                )
            log.append(f"OK   {label} ({len(ok)} files verified)")
            continue

        if step.action == "copy":
            if dry_run:
                log.append(f"SKIP {label} (dry-run: would extract {len(m.checksums)} files)")
                continue
            if not confirm(f"{label}\nExtract files to disk now?"):
                log.append(f"SKIP {label} (declined by human)")
                continue
            written, preserved = _extract(tar_bytes, dest_override, ts)
            log.append(
                f"OK   {label} ({written} files written"
                + (f", {preserved} pre-existing file(s) preserved as *.pre-restore-{ts}" if preserved else "")
                + ")"
            )
            continue

        if step.action == "load":
            # Generic utility cannot load state into an unknown runtime; it
            # coaches instead. Never executes anything.
            log.append(
                f"OK   {label} -- files are on disk; restart/reload the relevant "
                "tools yourself so they pick the restored state up."
            )
            continue

        if step.action == "smoke_check":
            if dry_run:
                log.append(f"SKIP {label} (dry-run)")
                continue
            bad = _smoke_check(m, dest_override)
            if bad:
                raise RestoreError(f"{label}: problems: " + "; ".join(bad[:10]))
            log.append(f"OK   {label}")
            continue

        if step.action == "run":
            binary = step.params["binary"]
            args = [str(a) for a in step.params["args"]]
            timeout = float(step.params["timeout"])
            if dry_run:
                log.append(f"SKIP {label} (dry-run: would run {binary} {' '.join(args)})")
                continue
            if not confirm(
                f"{label}\nThis EXECUTES: {binary} {' '.join(args)} "
                f"(timeout {timeout}s). Proceed?"
            ):
                log.append(f"SKIP {label} (declined by human)")
                continue
            proc = subprocess.run(
                [binary, *args], timeout=timeout, capture_output=True, text=True
            )
            if proc.returncode != 0:
                raise RestoreError(
                    f"{label}: exited {proc.returncode}: {proc.stderr.strip()[:500]}"
                )
            log.append(f"OK   {label}")
            continue

        # validate_steps() already guarantees we can't get here
        raise RestoreError(f"unhandled action {step.action!r}")  # pragma: no cover

    return log


def _extract(tar_bytes: bytes, dest_override: Optional[Path], ts: str) -> Tuple[int, int]:
    """Extract to original absolute paths (or under dest_override). Any
    pre-existing file is first renamed to <name>.pre-restore-<ts>."""
    written = 0
    preserved = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            rel = member.name.lstrip("/")
            target = (dest_override.expanduser() / rel) if dest_override else Path("/" + rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                backup = target.with_name(target.name + f".pre-restore-{ts}")
                shutil.move(str(target), str(backup))
                preserved += 1
            data = tar.extractfile(member).read()
            target.write_bytes(data)
            target.chmod(member.mode & 0o777)
            written += 1
    return written, preserved


def _smoke_check(m: manifest_mod.Manifest, dest_override: Optional[Path]) -> List[str]:
    problems = []
    for relpath, expected in m.checksums.items():
        rel = relpath.lstrip("/")
        target = (dest_override.expanduser() / rel) if dest_override else Path("/" + rel)
        if not target.exists():
            problems.append(f"missing after restore: {target}")
        elif sha256_file(target) != expected:
            problems.append(f"checksum mismatch after restore: {target}")
    return problems


def coaching_message(m: manifest_mod.Manifest) -> str:
    return m.coaching_message()


def refresher(m: manifest_mod.Manifest) -> str:
    """refresher_hint if the human provided one at backup time; otherwise a
    pointer at the restored notes. NEVER invents content."""
    if m.refresher_hint:
        return m.refresher_hint
    if m.notes:
        return f"Notes recorded at backup time: {m.notes}"
    return (
        "No refresher_hint was recorded. Read the restored memory/notes files "
        "listed above to rebuild context."
    )
