"""
tests/unit/test_merkle.py
==========================
Hash-chain and Merkle tree verification tests.
These tests verify that evidence pack integrity can be proven by
an independent JS-side reimplementation.
"""

from __future__ import annotations

import hashlib
import pytest
from turret_common.hashing import build_merkle_root, verify_merkle_root


class TestMerkleTree:

    def test_single_leaf(self) -> None:
        leaf = "a" * 64
        root = build_merkle_root([leaf])
        # Single leaf Merkle root is the leaf hash itself
        assert root == leaf

    def test_two_leaves(self) -> None:
        leaf1 = hashlib.sha256(b"file1.pdf").hexdigest()
        leaf2 = hashlib.sha256(b"file2.docx").hexdigest()
        root = build_merkle_root([leaf1, leaf2])
        # Two leaves: root = SHA-256(leaf1_bytes + leaf2_bytes)
        expected = hashlib.sha256(
            bytes.fromhex(leaf1) + bytes.fromhex(leaf2)
        ).hexdigest()
        assert root == expected

    def test_four_leaves(self) -> None:
        leaves = [hashlib.sha256(f"file{i}".encode()).hexdigest() for i in range(4)]
        root = build_merkle_root(leaves)
        # Manually compute expected root
        l1 = hashlib.sha256(bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1])).hexdigest()
        l2 = hashlib.sha256(bytes.fromhex(leaves[2]) + bytes.fromhex(leaves[3])).hexdigest()
        expected = hashlib.sha256(bytes.fromhex(l1) + bytes.fromhex(l2)).hexdigest()
        assert root == expected

    def test_verify_merkle_root_passes(self) -> None:
        leaves = [hashlib.sha256(f"file{i}".encode()).hexdigest() for i in range(3)]
        root = build_merkle_root(leaves)
        assert verify_merkle_root(leaves, root) is True

    def test_verify_merkle_root_fails_on_tamper(self) -> None:
        leaves = [hashlib.sha256(f"file{i}".encode()).hexdigest() for i in range(3)]
        root = build_merkle_root(leaves)
        # Tamper with one leaf
        tampered = leaves.copy()
        tampered[1] = "f" * 64
        assert verify_merkle_root(tampered, root) is False

    def test_verify_merkle_root_case_insensitive(self) -> None:
        leaves = [hashlib.sha256(b"a").hexdigest()]
        root = build_merkle_root(leaves)
        assert verify_merkle_root(leaves, root.upper()) is True


class TestEd25519Signing:

    def test_sign_and_verify(self, tmp_path) -> None:
        from turret_evidence.signer import generate_keypair, EvidenceSigner

        priv_path, pub_path = generate_keypair(tmp_path)
        signer = EvidenceSigner(priv_path, pub_path)

        merkle_root = "a" * 64
        sig = signer.sign_merkle_root(merkle_root, signer_id="test_signer")

        assert sig.signature_hex
        assert len(sig.signature_hex) == 128
        assert sig.signer_id == "test_signer"

        # Verify
        assert EvidenceSigner.verify_signature(sig, merkle_root) is True

    def test_tampered_merkle_fails_verification(self, tmp_path) -> None:
        from turret_evidence.signer import generate_keypair, EvidenceSigner

        priv_path, pub_path = generate_keypair(tmp_path)
        signer = EvidenceSigner(priv_path, pub_path)

        sig = signer.sign_merkle_root("a" * 64, signer_id="test")
        # Try to verify against different Merkle root
        assert EvidenceSigner.verify_signature(sig, "b" * 64) is False
