"""
turret_common.hashing
=====================
Cryptographic hashing utilities for TURRET OS.
All hash operations are deterministic and use OS-level secure primitives.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    """Return lowercase hex SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """
    Streaming SHA-256 of a file.  Reads in 1 MiB chunks to keep memory
    constant for large evidence files.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def blake3_file(path: Path, chunk_size: int = 1 << 20) -> str | None:
    """
    Streaming BLAKE3 of a file.  Returns None if the blake3 package is
    not available (graceful degradation for environments without it).
    """
    try:
        import blake3 as _blake3  # type: ignore[import]
    except ImportError:
        return None

    h = _blake3.blake3()
    with path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def sha256_path(source_path: str | Path) -> str:
    """
    Hash a *path string* (not file contents) for privacy-preserving storage.
    The actual path is never stored; only its SHA-256 is kept in FileRecord.
    """
    return sha256_bytes(str(source_path).encode("utf-8"))


def build_merkle_root(leaf_hashes: list[str]) -> str:
    """
    Build a binary SHA-256 Merkle tree over a list of hex leaf hashes.
    If the list has an odd number of leaves, the last leaf is duplicated
    (standard Bitcoin-style padding).

    Returns the hex-encoded Merkle root.
    """
    if not leaf_hashes:
        raise ValueError("Cannot build Merkle tree from empty list")

    # Convert hex strings to bytes
    nodes = [bytes.fromhex(h) for h in leaf_hashes]

    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])   # pad odd layer
        next_level: list[bytes] = []
        for i in range(0, len(nodes), 2):
            combined = nodes[i] + nodes[i + 1]
            next_level.append(hashlib.sha256(combined).digest())
        nodes = next_level

    return nodes[0].hex()


def verify_merkle_root(leaf_hashes: list[str], claimed_root: str) -> bool:
    """Verify that recomputed Merkle root matches claimed_root."""
    return build_merkle_root(leaf_hashes) == claimed_root.lower()
