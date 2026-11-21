"""End-to-end round-trip: create an encrypted backup of a throwaway
environment and restore it, entirely on local temp dirs."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_env_backup import cli, crypto, seed as seed_mod
from agent_env_backup.allowlist import AllowlistViolation, validate_steps
from agent_env_backup.restore import RestoreError, locate_backup, verify_seed_against_manifest


def run_cli(argv):
    return cli.main(argv)


class SeedTests(unittest.TestCase):
    def test_seed_roundtrip_and_checksum(self):
        s = seed_mod.generate_seed()
        self.assertEqual(len(s.split()), 12)
        self.assertTrue(seed_mod.verify_seed(s))

    def test_seed_rejects_typos_and_garbage(self):
        s = seed_mod.generate_seed().split()
        self.assertFalse(seed_mod.verify_seed(" ".join(["zzz"] * 12)))
        s[0] = "zebra" if s[0] != "zebra" else "abandon"
        self.assertFalse(seed_mod.verify_seed(" ".join(s)))
        self.assertFalse(seed_mod.verify_seed("too short"))

    def test_crypto_wrong_seed_fails_cleanly(self):
        s1, s2 = seed_mod.generate_seed(), seed_mod.generate_seed()
        blob = crypto.encrypt(s1, b"hello")
        self.assertEqual(crypto.decrypt(s1, blob), b"hello")
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(s2, blob)


class AllowlistTests(unittest.TestCase):
    def test_rejects_unknown_action(self):
        with self.assertRaises(AllowlistViolation):
            validate_steps([{"action": "exfiltrate"}])

    def test_run_requires_binary_args_timeout(self):
        with self.assertRaises(AllowlistViolation):
            validate_steps([{"action": "run", "params": {"binary": "/bin/true"}}])
        steps = validate_steps(
            [{"action": "run", "params": {"binary": "/bin/true", "args": [], "timeout": 5}}]
        )
        self.assertEqual(steps[0].action, "run")


class RoundTripTests(unittest.TestCase):
    def test_create_restore_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            # fake "agent environment"
            env = tmp / "fakeenv"
            (env / "config").mkdir(parents=True)
            (env / "config" / "settings.yaml").write_text("key: value\n")
            (env / "notes.md").write_text("remember the milk\n")

            backup_root = tmp / "backups"
            rc = run_cli([
                "create", "--include", str(env), "--dest", str(backup_root),
                "--notes", "test backup", "--refresher-hint", "read notes.md",
                "--yes",
            ])
            self.assertEqual(rc, 0)

            # only ONE backup dir; recover the seed from... nowhere -- the CLI
            # prints it and does not store it. For the test we create via the
            # library instead so we have the seed.
            # (The CLI path above already proved create works; do the restore
            # half via the library for deterministic seed access.)
            from agent_env_backup.backup import create_backup
            seed, backup_dir = create_backup(
                include_paths=[str(env)], categories=["config"],
                dest_dir=backup_root,
            )

            # sanity: on-disk payload is NOT plaintext
            blob = (backup_dir / "payload.tar.gz.enc").read_bytes()
            self.assertTrue(blob.startswith(crypto.MAGIC))
            self.assertNotIn(b"remember the milk", blob)

            # dry-run: verifies, writes nothing
            rc = run_cli([
                "restore", "--seed", seed, "--path", str(backup_dir),
                "--dest", str(tmp / "out-dry"), "--dry-run", "--yes",
            ])
            self.assertEqual(rc, 0)
            self.assertFalse((tmp / "out-dry").exists())

            # real restore into a dest override
            out = tmp / "out"
            rc = run_cli([
                "restore", "--seed", seed, "--path", str(backup_dir),
                "--dest", str(out), "--yes",
            ])
            self.assertEqual(rc, 0)
            restored = out / str(env).lstrip("/")
            self.assertEqual((restored / "notes.md").read_text(), "remember the milk\n")
            self.assertEqual((restored / "config" / "settings.yaml").read_text(), "key: value\n")

            # conservation: restoring again over existing files preserves them
            rc = run_cli([
                "restore", "--seed", seed, "--path", str(backup_dir),
                "--dest", str(out), "--yes",
            ])
            self.assertEqual(rc, 0)
            preserved = list(out.rglob("*.pre-restore-*"))
            self.assertTrue(preserved, "existing files should have been preserved, not clobbered")

    def test_wrong_seed_is_rejected_before_decrypt(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            env = tmp / "fakeenv"
            env.mkdir()
            (env / "a.txt").write_text("x")
            from agent_env_backup.backup import create_backup
            seed, backup_dir = create_backup([str(env)], ["config"], tmp / "b")
            wrong = seed_mod.generate_seed()
            lb = locate_backup(seed, backup_dir, tmp)
            with self.assertRaises(RestoreError):
                verify_seed_against_manifest(wrong, lb)


if __name__ == "__main__":
    unittest.main()
