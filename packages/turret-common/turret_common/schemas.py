"""
turret_common.schemas
=====================
All Pydantic v2 data contracts for the TURRET OS pipeline.
These schemas are shared across all five layers and define the
canonical data interchange format for the research paper experiments.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


# ── Node / Edge References ────────────────────────────────────────────────

class NodeRef(BaseModel):
    """Reference to a provenance graph node."""

    node_id: str = Field(..., description="Neo4j node element ID or synthetic UID")
    node_type: Literal["User", "Session", "File", "Channel", "Repo", "Device", "Printer"]
    label: str | None = Field(None, description="Human-readable display label")


# ── Hashes ────────────────────────────────────────────────────────────────

class Hashes(BaseModel):
    """Cryptographic fingerprint of the ingested file."""

    sha256: str = Field(..., min_length=64, max_length=64)
    blake3: str | None = Field(None, min_length=64, max_length=64)
    md5_rfc3227: str | None = Field(None, description="RFC 3227 image MD5; populated by L4")

    @field_validator("sha256", "blake3", mode="before")
    @classmethod
    def _lower(cls, v: str | None) -> str | None:
        return v.lower() if v else v


# ── Auth Chain ────────────────────────────────────────────────────────────

class AuthChain(BaseModel):
    """Authentication and delegation chain at time of file access."""

    signed_by_user: str = Field(..., description="Primary authenticated user UID")
    delegated_as: list[str] = Field(default_factory=list, description="Proxy / delegation chain")
    session_token_hash: str = Field(..., description="SHA-256 of session token; never raw token")
    ip_at_open: str | None = None
    device_id: str | None = None
    clearance_at_open: Literal["open", "cui", "secret", "ts", "ts_sci"] | None = None


# ── File Record (L1 output) ───────────────────────────────────────────────

class FileRecord(BaseModel):
    """
    Canonical output of the L1 Harvest layer.
    One row per unique (file, access_event) pair.
    """

    record_id: UUID = Field(..., description="Globally unique record identifier")
    ingest_ts: datetime = Field(..., description="ISO 8601 timestamp of harvest")
    source_path_hash: str = Field(
        ..., description="SHA-256 of the canonical source path; path itself not stored"
    )
    format: Literal[
        "docx", "xlsx", "pptx", "pdf", "dwg", "eml",
        "git-commit", "sharepoint", "teams", "jpeg", "png", "tiff"
    ]
    size_bytes: int = Field(..., ge=0)
    classifier: Literal["open", "cui", "secret", "ts", "ts_sci"]
    tika_xdm: dict[str, Any] = Field(default_factory=dict, description="Apache Tika XDM metadata")
    exif: dict[str, Any] | None = Field(None, description="ExifTool output; None for non-image formats")
    custom: dict[str, Any] = Field(default_factory=dict, description="Format-specific parsed fields")
    auth_chain: AuthChain
    hashes: Hashes

    model_config = {"frozen": False}


# ── Provenance Edge (L2 output) ───────────────────────────────────────────

class ProvenanceEdge(BaseModel):
    """
    Directed edge in the W3C PROV provenance knowledge graph.
    Persisted in Neo4j and serialised to PROV-JSON-LD sidecar.
    """

    edge_id: str = Field(..., description="Unique edge identifier (UUID4 hex)")
    src: NodeRef
    dst: NodeRef
    type: Literal[
        "EDITED_BY", "OPENED_ON", "EMAILED_TO", "UPLOADED_TO",
        "COMMITTED_TO", "PRINTED_BY", "CO_EDITED_WITH"
    ]
    ts: datetime = Field(..., description="Timestamp of the provenance event")
    client_app: str | None = None
    revision_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Rule Hit ──────────────────────────────────────────────────────────────

class RuleHit(BaseModel):
    """Single rule triggered within a detection window."""

    rule_id: str
    rule_name: str
    weight: float = Field(..., ge=0.0, le=1.0)
    triggered_at: datetime
    evidence_fields: dict[str, Any] = Field(default_factory=dict)
    severity: Literal["low", "medium", "high", "critical"]


# ── Detection Alert (L3 output) ───────────────────────────────────────────

class DetectionAlert(BaseModel):
    """
    Output of the L3 detection layer (rules + GNN).
    Contains both rule hits and GNN-derived scores with explanations.
    """

    alert_id: UUID = Field(..., description="Globally unique alert identifier")
    user_uid: str
    window_start: datetime
    window_end: datetime
    score: float = Field(..., ge=0.0, le=1.0, description="Normalised combined detection score")
    contributing_rules: list[RuleHit] = Field(default_factory=list)
    subgraph_nodes: list[NodeRef] = Field(default_factory=list)
    subgraph_edges: list[ProvenanceEdge] = Field(default_factory=list)
    shap_values: dict[str, float] = Field(
        default_factory=dict, description="Feature name → SHAP value"
    )
    counterfactual_drop: float = Field(
        0.0, description="Score drop if top contributing rule/edge is removed"
    )
    gnn_explainer_fidelity: float | None = Field(
        None, description="GNNExplainer fidelity score for this alert's ego-subgraph"
    )
    nl_explanation: str | None = Field(None, description="NL template-generated explanation")

    model_config = {"frozen": False}


# ── Chain of Custody ─────────────────────────────────────────────────────

class CustodyOp(BaseModel):
    """Single chain-of-custody operation recorded in the evidence pack."""

    op_id: str
    op_type: Literal["collect", "acquire", "transfer", "analyse", "present"]
    actor: str
    ts: datetime
    tool: str | None = None
    hash_before: str | None = None
    hash_after: str | None = None
    notes: str | None = None


# ── Ed25519 Signature ─────────────────────────────────────────────────────

class Ed25519Sig(BaseModel):
    """Ed25519 digital signature over the evidence pack Merkle root."""

    signer_id: str
    signature_hex: str = Field(..., min_length=128, max_length=128)
    public_key_hex: str = Field(..., min_length=64, max_length=64)
    signed_at: datetime
    signed_data_desc: str = Field(..., description="Human-readable description of what was signed")


# ── Evidence Pack (L4 output) ─────────────────────────────────────────────

class EvidencePack(BaseModel):
    """
    ISO/IEC 27043-aligned forensic evidence package.
    Output of the L4 Evidence layer; one zip bundle per alert.
    """

    evidence_id: str = Field(..., description="Unique evidence package identifier")
    alert: DetectionAlert
    prov_jsonld_blob_key: str = Field(..., description="S3/local path to PROV-JSON-LD file")
    file_hashes: list[str] = Field(
        default_factory=list, description="SHA-256 hashes of all evidence files"
    )
    merkle_root: str = Field(..., description="SHA-256 Merkle root over all file_hashes")
    rfc3227_image_md5: str | None = Field(
        None, description="MD5 of forensic disk image if collected per RFC 3227"
    )
    chain_of_custody: list[CustodyOp] = Field(default_factory=list)
    signatures: list[Ed25519Sig] = Field(default_factory=list)
    iso27043_attributes: dict[str, bool] = Field(
        default_factory=dict,
        description="ISO/IEC 27043 readiness attribute coverage checklist"
    )

    model_config = {"frozen": False}
