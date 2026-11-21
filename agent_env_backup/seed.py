"""Seed generation, encoding, and verification.

Seed format (NOT BIP-39 wallet compatible, intentionally -- this is a backup
locator/integrity token, not a cryptocurrency key):

  - 128 bits of random entropy
  - + 4-bit checksum = sha256(entropy)[0] >> 4   (top nibble of first byte)
  - = 132 bits, split into twelve 11-bit groups
  - each group indexes into the 2048-word BIP-39 English wordlist for a
    human-typeable, human-verifiable 12-word phrase.

The same wordlist is reused purely because it is a well-reviewed, public
domain, unambiguous (no prefix collisions, no look-alikes) 2048-word list --
not for any wallet interoperability claim.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from .wordlist import WORDLIST

_WORD_INDEX = {w: i for i, w in enumerate(WORDLIST)}


class InvalidSeed(ValueError):
    pass


def generate_seed() -> str:
    """Generate a fresh 12-word seed phrase."""
    entropy = secrets.token_bytes(16)  # 128 bits
    return _entropy_to_phrase(entropy)


def _entropy_to_phrase(entropy: bytes) -> str:
    checksum_byte = hashlib.sha256(entropy).digest()[0]
    checksum_bits = checksum_byte >> 4  # top 4 bits

    bits = int.from_bytes(entropy, "big") << 4 | checksum_bits
    total_bits = 128 + 4

    words = []
    for i in range(12):
        shift = total_bits - (i + 1) * 11
        idx = (bits >> shift) & 0x7FF
        words.append(WORDLIST[idx])
    return " ".join(words)


def verify_seed(phrase: str) -> bool:
    """Return True iff phrase is a well-formed, checksum-valid 12-word seed."""
    try:
        words = phrase.strip().lower().split()
        if len(words) != 12:
            return False
        bits = 0
        for w in words:
            if w not in _WORD_INDEX:
                return False
            bits = (bits << 11) | _WORD_INDEX[w]
        checksum_bits = bits & 0xF
        entropy_int = bits >> 4
        entropy = entropy_int.to_bytes(16, "big")
        expected = hashlib.sha256(entropy).digest()[0] >> 4
        return expected == checksum_bits
    except Exception:
        return False


def seed_fingerprint(phrase: str, length: int = 8) -> str:
    """Short, non-secret identifier derived from a seed (safe to use as a
    directory/object name -- does not allow recovering the seed)."""
    digest = hashlib.sha256(f"agent-env-backup:fingerprint:{phrase.strip().lower()}".encode()).hexdigest()
    return digest[:length]


def payload_hmac(phrase: str, payload_bytes: bytes) -> str:
    """HMAC-SHA256 of the payload bytes, keyed by the seed phrase.

    Used to bind a payload to its seed: restore recomputes this and compares,
    so a payload can't be silently swapped for a different one under the same
    seed, and a mistyped seed is caught at restore time instead of partway
    through acting on bad data.
    """
    key = phrase.strip().lower().encode()
    return hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
