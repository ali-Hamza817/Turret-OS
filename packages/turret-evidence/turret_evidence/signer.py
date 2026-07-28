"""
turret_evidence.signer
========================
Ed25519 digital signature utilities for TURRET OS evidence packs.
Uses the cryptography library (libsodium-backed); never homegrown crypto.

Security:
- Private key loaded from file path set in config/environment; never hardcoded.
- Signature covers the Merkle root (hex string) encoded as UTF-8 bytes.
- Verification is always performed before returning a signature object.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
    load_pem_private_key,
    load_pem_public_key,
)

from turret_common.schemas import Ed25519Sig

logger = logging.getLogger(__name__)


class EvidenceSigner:
    """
    Sign and verify TURRET OS evidence packs with Ed25519.
    """

    def __init__(self, private_key_path: Path, public_key_path: Path) -> None:
        self._private_key: Ed25519PrivateKey = self._load_private_key(private_key_path)
        self._public_key: Ed25519PublicKey = self._load_public_key(public_key_path)
        self._public_key_hex = self._public_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        ).hex()

    @staticmethod
    def _load_private_key(path: Path) -> Ed25519PrivateKey:
        pem = path.read_bytes()
        key = load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"Key at {path} is not an Ed25519 private key")
        return key

    @staticmethod
    def _load_public_key(path: Path) -> Ed25519PublicKey:
        pem = path.read_bytes()
        key = load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"Key at {path} is not an Ed25519 public key")
        return key

    def sign_merkle_root(self, merkle_root: str, signer_id: str) -> Ed25519Sig:
        """
        Sign the Merkle root hex string and return an Ed25519Sig object.
        The signature is verified immediately before returning.
        """
        data = merkle_root.encode("utf-8")
        sig_bytes = self._private_key.sign(data)
        sig_hex = sig_bytes.hex()

        # Verify immediately (fail-fast on key mismatch)
        self._public_key.verify(sig_bytes, data)

        return Ed25519Sig(
            signer_id=signer_id,
            signature_hex=sig_hex,
            public_key_hex=self._public_key_hex,
            signed_at=datetime.now(tz=timezone.utc),
            signed_data_desc=f"SHA-256 Merkle root of evidence pack for signer {signer_id}",
        )

    @staticmethod
    def verify_signature(sig: Ed25519Sig, merkle_root: str) -> bool:
        """
        Verify an Ed25519Sig against the given Merkle root.
        Returns True if valid, False otherwise.
        """
        try:
            pub_key_bytes = bytes.fromhex(sig.public_key_hex)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _PK
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            # Reconstruct from raw bytes
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            key = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
            sig_bytes = bytes.fromhex(sig.signature_hex)
            key.verify(sig_bytes, merkle_root.encode("utf-8"))
            return True
        except Exception as exc:
            logger.warning("Signature verification failed: %s", exc)
            return False


def generate_keypair(output_dir: Path) -> tuple[Path, Path]:
    """
    Generate a new Ed25519 keypair and write PEM files.
    Used by scripts/gen_keys.py.

    Returns: (private_key_path, public_key_path)
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_path = output_dir / "signing_key.pem"
    pub_path = output_dir / "verify_key.pem"

    priv_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    pub_path.write_bytes(
        public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )

    logger.info("Ed25519 keypair written to %s", output_dir)
    return priv_path, pub_path
