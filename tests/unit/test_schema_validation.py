"""
tests/unit/test_schema_validation.py
======================================
Pydantic schema validation unit tests across all TURRET OS data models.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4
import pytest
from turret_common.schemas import DetectionAlert, CustodyOp, RuleHit, EvidencePack, Ed25519Sig


def test_rule_hit_schema() -> None:
    hit = RuleHit(
        rule_id="CLEARANCE_VIOLATION",
        rule_name="Clearance Breach",
        weight=0.25,
        triggered_at=datetime.now(tz=timezone.utc),
        evidence_fields={"user": "U1", "file": "secret.pdf"},
        severity="critical",
    )
    dumped = hit.model_dump(mode="json")
    reloaded = RuleHit(**dumped)
    assert reloaded.rule_id == "CLEARANCE_VIOLATION"
    assert reloaded.severity == "critical"


def test_detection_alert_schema() -> None:
    alert = DetectionAlert(
        alert_id=uuid4(),
        user_uid="U0001",
        window_start=datetime.now(tz=timezone.utc),
        window_end=datetime.now(tz=timezone.utc),
        score=0.92,
        contributing_rules=[],
        subgraph_nodes=[{"node_id": "N1", "node_type": "User", "label": "U1"}],
        subgraph_edges=[],
        shap_values={"CLEARANCE_VIOLATION": 0.4},
    )
    dumped = alert.model_dump(mode="json")
    reloaded = DetectionAlert(**dumped)
    assert reloaded.user_uid == "U0001"
    assert reloaded.score == 0.92


def test_custody_op_schema() -> None:
    op = CustodyOp(
        op_id="op-1",
        op_type="collect",
        actor="harvest_service",
        ts=datetime.now(tz=timezone.utc),
        tool="turret-harvest",
    )
    dumped = op.model_dump(mode="json")
    reloaded = CustodyOp(**dumped)
    assert reloaded.op_id == "op-1"
