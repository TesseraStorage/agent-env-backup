"""Command-line interface.

  agent-env-backup create  --include PATH... --dest DIR [--tessera] [--yes]
  agent-env-backup restore [--path DIR | --search-dir DIR] [--dest DIR]
                           [--dry-run] [--yes]
  agent-env-backup verify  (alias for restore --dry-run)

The seed is NEVER taken from a plain command-line argument by default (it
would land in shell history); it is prompted for interactively. For
automation/tests you may pass --seed or set AEB_SEED, at your own risk.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from . import backup as backup_mod
from . import restore as restore_mod


def _ask_yes_no(prompt: str) -> bool:
    try:
        ans = input(f"{prompt} [yes/no]: ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def _get_seed(args) -> str:
    if args.seed:
        return args.seed
    env = os.environ.get("AEB_SEED")
    if env:
        return env
    return getpass.getpass("Seed phrase (12 words, input hidden): ")


def cmd_create(args) -> int:
    includes: List[str] = list(args.include or [])

    if not includes and not args.yes:
        print("Suggested categories (nothing is read or written yet):")
        for cat, examples in backup_mod.suggest_categories().items():
            ex = f"  e.g. {', '.join(examples)}" if examples else ""
            print(f"  - {cat}{ex}")
        print()
        print("Enter paths to include, one per line. Empty line to finish.")
        while True:
            try:
                line = input("include> ").strip()
            except EOFError:
                break
            if not line:
                break
            includes.append(line)

    if not includes:
        print("error: no include paths given", file=sys.stderr)
        return 2

    existing = [p for p in includes if Path(p).expanduser().exists()]
    missing = [p for p in includes if not Path(p).expanduser().exists()]

    print("\n=== Backup plan ===")
    print(f"Destination : {args.dest}")
    print(f"Tessera copy: {'requested (STUB: no real upload in this release)' if args.tessera else 'no'}")
    print(f"Include list ({len(existing)} existing):")
    for p in existing:
        print(f"  + {p}")
    for p in missing:
        print(f"  ! {p}  (does not exist -- will be skipped)")
    if args.notes:
        print(f"Notes       : {args.notes}")

    if not args.yes and not _ask_yes_no("\nWrite an encrypted backup of exactly these files?"):
        print("aborted; nothing was written")
        return 1

    seed, backup_dir = backup_mod.create_backup(
        include_paths=existing,
        categories=list(backup_mod.suggest_categories().keys()),
        dest_dir=Path(args.dest),
        upload_to_tessera=args.tessera,
        notes=args.notes or "",
        source_host=os.uname().nodename if hasattr(os, "uname") else "",
        refresher_hint=args.refresher_hint,
    )

    print(f"\nBackup written to: {backup_dir}")
    print(f"  payload   : payload.tar.gz.enc (AES-256-GCM; key from your seed)")
    print(f"  checklist : RECONSTITUTE.yaml")
    print("\n=== YOUR SEED -- write this down, it is shown ONCE and never stored ===")
    print(f"  {seed}")
    print("=========================================================================")
    print("Without these 12 words the backup CANNOT be decrypted. By design there")
    print("is no recovery mechanism and no copy of the seed anywhere on disk.")
    return 0


def _confirm_factory(yes: bool):
    if yes:
        return lambda prompt: True
    return lambda prompt: _ask_yes_no(prompt)


def cmd_restore(args) -> int:
    seed = _get_seed(args)
    dry = bool(args.dry_run)

    try:
        lb = restore_mod.locate_backup(
            seed,
            path=Path(args.path) if args.path else None,
            search_dir=Path(args.search_dir),
        )
    except restore_mod.RestoreError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    print(f"Found backup: {lb.backup_dir}")

    # allow-list validation happens before ANY step executes
    try:
        steps = restore_mod.plan_steps(lb.manifest)
    except ValueError as e:
        print(f"error: manifest failed allow-list validation: {e}", file=sys.stderr)
        return 2

    print()
    print(restore_mod.human_summary(lb.manifest, steps))
    print()

    try:
        restore_mod.verify_seed_against_manifest(seed, lb)
    except restore_mod.RestoreError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print("Seed verified against manifest (fingerprint + payload HMAC). ")

    if dry:
        print("\n[dry-run] No files will be written and nothing will be decrypted")
        print("[dry-run] unless you explicitly authorize it below.")
        if not _confirm_factory(args.yes)(
            "Authorize in-memory decryption to verify file checksums? (still writes nothing)"
        ):
            print("[dry-run] stopping before decryption; archive is intact, seed is valid")
            return 0

    try:
        tar_bytes = restore_mod.decrypt_payload(seed, lb)
    except restore_mod.RestoreError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    confirm = _confirm_factory(args.yes)
    try:
        log = restore_mod.execute_steps(
            steps, lb.manifest, tar_bytes,
            dest_override=Path(args.dest) if args.dest else None,
            confirm=confirm, dry_run=dry,
        )
    except restore_mod.RestoreError as e:
        print(f"\nerror during restore: {e}", file=sys.stderr)
        return 1

    print("\n=== Restore log ===")
    for line in log:
        print(" ", line)

    if dry:
        print("\n[dry-run] complete. Nothing was written.")
        return 0

    print()
    print(restore_mod.coaching_message(lb.manifest))
    print()
    print("Refresher:")
    print(" ", restore_mod.refresher(lb.manifest))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-env-backup",
        description="Human-controlled encrypted backup/restore for agent environments. "
        "The seed phrase is the only key; nothing is written unencrypted.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("create", help="create an encrypted backup")
    c.add_argument("--include", action="append", default=[],
                   help="path to include (repeatable)")
    c.add_argument("--dest", required=True, help="directory to write the backup into")
    c.add_argument("--tessera", action="store_true",
                   help="plan an optional Tessera copy (STUB: no real upload in this release)")
    c.add_argument("--notes", default="", help="free-text notes stored in the checklist")
    c.add_argument("--refresher-hint", default=None,
                   help="short human-written hint shown after a future restore")
    c.add_argument("--yes", action="store_true", help="skip confirmation prompts (automation)")
    c.set_defaults(func=cmd_create)

    r = sub.add_parser("restore", help="restore from an encrypted backup")
    r.add_argument("--seed", default=None, help="12-word seed (prefer interactive prompt)")
    r.add_argument("--path", default=None, help="backup dir (or its parent)")
    r.add_argument("--search-dir", default=".", help="where to look when --path is not given")
    r.add_argument("--dest", default=None,
                   help="extract under this dir instead of original absolute paths")
    r.add_argument("--dry-run", action="store_true", help="verify only; write nothing")
    r.add_argument("--yes", action="store_true", help="skip confirmation prompts (automation)")
    r.set_defaults(func=cmd_restore)

    v = sub.add_parser("verify", help="alias for restore --dry-run")
    v.add_argument("--seed", default=None)
    v.add_argument("--path", default=None)
    v.add_argument("--search-dir", default=".")
    v.add_argument("--dest", default=None)
    v.add_argument("--dry-run", action="store_true", default=True)
    v.add_argument("--yes", action="store_true")
    v.set_defaults(func=cmd_restore)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
