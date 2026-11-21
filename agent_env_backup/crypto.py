"""Seed-passphrase encryption for the payload.

The human's seed phrase is the ONLY key material. Nothing is written to disk
or transmitted unencrypted.

Construction:
  key    = scrypt(seed_phrase_normalized, salt, n=2**15, r=8, p=1, dklen=32)
  cipher = AES-256-GCM(key, random 12-byte nonce)
  blob   = salt(32) || nonce(12) || ciphertext+tag

The salt and nonce are stored alongside the ciphertext in the payload file
header; they are not secret. Wrong seed => GCM tag verification fails =>
clean, immediate "wrong passphrase or corrupted archive" error, never a
half-decrypted mess.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32
_SALT_LEN = 32
_NONCE_LEN = 12
MAGIC = b"AEB1"  # agent-env-backup format v1


class DecryptionError(ValueError):
    pass


def _normalize(seed: str) -> bytes:
    return " ".join(seed.strip().lower().split()).encode("utf-8")


def derive_key(seed: str, salt: bytes) -> bytes:
    # 128*N*r*p = 32 MiB of work memory; OpenSSL's default maxmem is below
    # that, so raise the cap explicitly (64 MiB) rather than weakening the KDF.
    return hashlib.scrypt(
        _normalize(seed), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        dklen=_KEY_LEN, maxmem=64 * 1024 * 1024,
    )


def encrypt(seed: str, plaintext: bytes) -> bytes:
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key = derive_key(seed, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, MAGIC)
    return MAGIC + salt + nonce + ct


def decrypt(seed: str, blob: bytes) -> bytes:
    min_len = len(MAGIC) + _SALT_LEN + _NONCE_LEN + 16
    if len(blob) < min_len or not blob.startswith(MAGIC):
        raise DecryptionError("not an agent-env-backup v1 payload (bad magic/length)")
    salt = blob[len(MAGIC):len(MAGIC) + _SALT_LEN]
    nonce = blob[len(MAGIC) + _SALT_LEN:len(MAGIC) + _SALT_LEN + _NONCE_LEN]
    ct = blob[len(MAGIC) + _SALT_LEN + _NONCE_LEN:]
    key = derive_key(seed, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, MAGIC)
    except Exception:
        raise DecryptionError(
            "decryption failed: wrong seed phrase or corrupted/tampered archive"
        ) from None
