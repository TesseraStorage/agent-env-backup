# agent-env-backup

A small, human-controlled CLI for **encrypted backups of an agent (or human)
working environment**: config files, memory/notes, handoffs, CLI state, and
any credentials the human explicitly chooses to include.

- **Open source, MIT licensed.** Not signed by, affiliated with, or exclusive
  to any product. Anyone can use it, with or without Tessera.
- **Local-first.** Everything works with zero network access. An optional
  copy to a Tessera destination (ordinary client object on the existing
  `per_action` rail — no privileged paths, no special metadata, no billing
  exceptions) is planned; in this release that destination is a documented
  stub and **no network calls are made at all**.
- **The human acts; the tool asks.** Every mutating step sits behind an
  explicit confirmation. A restore can be coached by an agent reading the
  checklist aloud, but nothing writes, decrypts, or executes without the
  human saying yes at the gate.

## The encryption guarantee

**Nothing is ever written to disk or transmitted in cleartext.**

- Your **12-word seed phrase is the only key**. It is generated at backup
  time, shown exactly once, and never stored anywhere by this tool.
- The payload is encrypted **in memory, before any disk write**, with
  AES-256-GCM. The key is derived from your seed with scrypt
  (n=2^15, r=8, p=1).
- The on-disk artifact is `payload.tar.gz.enc` plus a plain-text
  `RECONSTITUTE.yaml` checklist. The checklist contains file **paths**,
  checksums, and restore steps — never file contents, never the seed.
- Wrong seed → clean, immediate authentication failure (GCM tag). There is
  no partial decrypt and no recovery backdoor. **If you lose the seed, the
  backup is unrecoverable. That is deliberate.**

## Install

```bash
pip install .
# or run without installing:
python -m agent_env_backup.cli --help
```

## Create a backup

```bash
agent-env-backup create --include ~/.config/myapp --include ~/notes --dest ~/backups
```

The tool prints the exact include list and waits for your explicit `yes`
before writing anything. Run without `--include` for an interactive prompt
that suggests categories (config, memory/notes, handoffs, CLI state).
It then prints your 12-word seed **once**. Write it down.

## Restore

```bash
agent-env-backup restore --path ~/backups/agent-env-backup-<fingerprint> --dest ~/restore-target
```

You will be prompted for the seed (input hidden; never taken from a plain
CLI argument by default so it doesn't land in shell history). The tool:

1. Verifies the seed against the archive (wordlist checksum → manifest
   fingerprint → seed-bound payload HMAC) **before decrypting anything**.
2. Shows the full step plan, flagging any step that touches credentials,
   the network, or executes a binary.
3. Walks the checklist steps — each behind its own confirmation gate —
   using a fixed action allow-list (`verify_seed`, `verify_checksums`,
   `copy`, `load`, `smoke_check`, and `run` with explicit
   binary+args+timeout only). A manifest containing any other action is
   rejected before anything runs.
4. Preserves, never clobbers: any pre-existing file at the destination is
   renamed to `*.pre-restore-<timestamp>` before a restored file takes its
   place.

Verify-only mode (writes nothing, decrypts only if you authorize it):

```bash
agent-env-backup verify --path ~/backups/agent-env-backup-<fingerprint>
```

## "Drop this prompt" — for the alive-again chat

Paste this into a fresh chat with any agent to get coached through a restore:

> I have an encrypted environment backup made with the open-source
> `agent-env-backup` tool. I have the 12-word seed phrase; you will never
> see it. Please read the `RECONSTITUTE.yaml` checklist in the backup
> directory I point you at, then walk me through restoring my environment
> step by step. Rules: you explain, I act. Ask for my explicit confirmation
> before every step. Never ask me to paste the seed into chat. If a step
> touches credentials, the network, or runs a program, flag it clearly
> before we do it. If anything fails verification, stop and tell me —
> do not improvise.

Expected tone of a successful restore (locked):

> "Welcome back. I think we've got everything together, but some workflow
> may need a little jump-starting. All files saved on [date] are present
> and verified."

## Disclaimers

- **You are responsible for the seed.** No one — including this tool's
  authors and any service you upload the encrypted archive to — can recover
  it or decrypt the archive without it.
- The plain-text checklist reveals file **paths** (not contents). Treat the
  backup directory as sensitive accordingly.
- `run` steps in a checklist execute real programs. The allow-list forces
  them to be explicit (binary + args + timeout) and gated, but you should
  still read them before saying yes.
- The optional Tessera upload is **not implemented in this release** (see
  `agent_env_backup/tessera_stub.py` for the exact documented design:
  ordinary client objects, `per_action` rail, one-way upload, no sync).
  This release makes **no network calls whatsoever**.
- This tool is not affiliated with or signed by Tessera or any other
  product; Tessera consumes the identical public package unchanged.

## Development

```bash
python -m unittest discover -s tests -v
```

Layout:

- `agent_env_backup/seed.py` — 12-word seed (128-bit entropy + checksum,
  BIP-39 wordlist used purely as a public-domain word encoding; **not**
  wallet-compatible)
- `agent_env_backup/crypto.py` — scrypt KDF + AES-256-GCM
- `agent_env_backup/backup.py` — encrypted create path
- `agent_env_backup/restore.py` — gated restore path
- `agent_env_backup/allowlist.py` — the restore action allow-list
- `agent_env_backup/manifest.py` — `RECONSTITUTE.yaml` schema
- `agent_env_backup/tessera_stub.py` — documented, unimplemented Tessera rail
