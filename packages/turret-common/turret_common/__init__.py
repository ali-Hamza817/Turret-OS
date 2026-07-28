"""turret-common: shared schemas, hashing, and configuration for TURRET OS."""

from turret_common.schemas import (
    FileRecord,
    AuthChain,
    Hashes,
    NodeRef,
    ProvenanceEdge,
    RuleHit,
    DetectionAlert,
    CustodyOp,
    Ed25519Sig,
    EvidencePack,
)
from turret_common.hashing import sha256_file, blake3_file, sha256_bytes
from turret_common.config import TurretSettings, get_settings

__all__ = [
    "FileRecord",
    "AuthChain",
    "Hashes",
    "NodeRef",
    "ProvenanceEdge",
    "RuleHit",
    "DetectionAlert",
    "CustodyOp",
    "Ed25519Sig",
    "EvidencePack",
    "sha256_file",
    "blake3_file",
    "sha256_bytes",
    "TurretSettings",
    "get_settings",
]
