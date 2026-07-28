"""
tests/unit/test_harvest.py
===========================
Unit tests for the L1 harvest layer.
Tests: golden fixture outputs, hash determinism, parser isolation.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def sample_docx(tmp_path: Path) -> Path:
    """Create a minimal DOCX file for testing."""
    from docx import Document
    doc = Document()
    doc.core_properties.author = "Test Author"
    doc.core_properties.title = "Test Document"
    doc.add_paragraph("Hello, TURRET OS!")
    out = tmp_path / "test.docx"
    doc.save(str(out))
    return out


@pytest.fixture
def sample_text_file(tmp_path: Path) -> Path:
    """Create a text file (unsupported format — should be skipped)."""
    f = tmp_path / "readme.txt"
    f.write_text("This format is not supported.")
    return f


# ── Hash Determinism ──────────────────────────────────────────────────────

class TestHashing:
    def test_sha256_determinism(self, tmp_path: Path) -> None:
        """SHA-256 of same content must be identical across runs."""
        from turret_common.hashing import sha256_file

        f = tmp_path / "data.bin"
        content = b"TURRET OS determinism test " * 1000
        f.write_bytes(content)

        hash1 = sha256_file(f)
        hash2 = sha256_file(f)
        assert hash1 == hash2
        assert len(hash1) == 64
        assert hash1 == hashlib.sha256(content).hexdigest()

    def test_merkle_root_determinism(self) -> None:
        """Merkle root of same leaf set must be identical."""
        from turret_common.hashing import build_merkle_root

        leaves = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]
        root1 = build_merkle_root(leaves)
        root2 = build_merkle_root(leaves)
        assert root1 == root2
        assert len(root1) == 64

    def test_merkle_tamper_detection(self) -> None:
        """Changing any leaf must change the Merkle root."""
        from turret_common.hashing import build_merkle_root

        leaves = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]
        root_original = build_merkle_root(leaves)

        # Tamper with one leaf
        leaves_tampered = leaves.copy()
        leaves_tampered[1] = "f" * 64
        root_tampered = build_merkle_root(leaves_tampered)

        assert root_original != root_tampered

    def test_merkle_odd_leaves(self) -> None:
        """Odd number of leaves should be padded and produce valid root."""
        from turret_common.hashing import build_merkle_root

        leaves = ["a" * 64, "b" * 64, "c" * 64]  # odd
        root = build_merkle_root(leaves)
        assert len(root) == 64

    def test_merkle_empty_raises(self) -> None:
        from turret_common.hashing import build_merkle_root

        with pytest.raises(ValueError):
            build_merkle_root([])

    def test_sha256_path_hides_path(self) -> None:
        """sha256_path should return a hash, not the original path."""
        from turret_common.hashing import sha256_path

        path = "/classified/secret/file.docx"
        result = sha256_path(path)
        assert path not in result
        assert len(result) == 64


# ── DOCX Parser ───────────────────────────────────────────────────────────

class TestDocxParser:
    def test_extract_returns_required_keys(self, sample_docx: Path) -> None:
        from turret_harvest.parsers.docx_parser import DocxParser

        parser = DocxParser()
        result = parser.extract(sample_docx)

        assert "tika_xdm" in result
        assert "exif" in result
        assert "custom" in result
        assert result["exif"] is None  # DOCX has no EXIF

    def test_extract_captures_author(self, sample_docx: Path) -> None:
        from turret_harvest.parsers.docx_parser import DocxParser

        parser = DocxParser()
        result = parser.extract(sample_docx)
        assert "Test Author" in result["tika_xdm"].get("dc:creator", "")

    def test_extract_graceful_on_corrupt_file(self, tmp_path: Path) -> None:
        """Parser must not raise on corrupt/empty files."""
        from turret_harvest.parsers.docx_parser import DocxParser

        corrupt = tmp_path / "corrupt.docx"
        corrupt.write_bytes(b"not a docx file at all")

        parser = DocxParser()
        result = parser.extract(corrupt)
        # Should return partial result with parse_error, not raise
        assert "tika_xdm" in result or "custom" in result


# ── Sink Schema Validation ────────────────────────────────────────────────

class TestParquetSink:
    def test_flush_produces_valid_parquet(self, tmp_path: Path) -> None:
        import uuid
        from datetime import datetime, timezone
        from turret_harvest.sink import ParquetSink
        import pyarrow.parquet as pq

        sink = ParquetSink(tmp_path / "out.parquet")
        sink.write({
            "record_id": uuid.uuid4(),
            "ingest_ts": datetime.now(tz=timezone.utc),
            "source_path_hash": "a" * 64,
            "format": "docx",
            "size_bytes": 1024,
            "classifier": "open",
            "tika_xdm": {"dc:creator": "Author"},
            "exif": None,
            "custom": {},
            "auth_chain": {
                "signed_by_user": "test_user",
                "delegated_as": [],
                "session_token_hash": "b" * 64,
                "device_id": None,
            },
            "hashes": {"sha256": "c" * 64, "blake3": None},
        })
        path = sink.flush()

        assert path.exists()
        table = pq.read_table(str(path))
        assert table.num_rows == 1
        assert "record_id" in table.schema.names


# ── Rule Engine ───────────────────────────────────────────────────────────

class TestRuleEngine:
    @pytest.fixture
    def engine(self) -> "RuleEngine":
        from turret_detect.rules.loader import load_rules
        return load_rules("config/espionage_rules.yaml")

    def test_clearance_violation_triggers(self, engine) -> None:
        activity = {
            "file_classifier": "ts",
            "user_max_clearance": "cui",
        }
        score, hits = engine.evaluate(activity)
        rule_ids = [h.rule_id for h in hits]
        assert "CLEARANCE_VIOLATION" in rule_ids

    def test_no_trigger_on_benign_activity(self, engine) -> None:
        activity = {
            "file_classifier": "open",
            "user_max_clearance": "ts_sci",
            "access_novelty_score": 0.5,
            "access_hour": 10,
            "off_hours_multiplier": 1.0,
            "session_user": "user_a",
            "doc_author": "user_a",
            "action": "view",
            "device_clearance": "ts_sci",
            "copy_to_removable": False,
            "badge_gap_minutes": 999,
            "metadata_stripped": False,
            "followed_by_outbound": False,
        }
        score, hits = engine.evaluate(activity)
        assert score < engine.alert_threshold
        assert len(hits) == 0

    def test_metadata_strip_triggers(self, engine) -> None:
        activity = {
            "metadata_stripped": True,
            "followed_by_outbound": True,
            "outbound_gap_minutes": 30,
        }
        score, hits = engine.evaluate(activity)
        rule_ids = [h.rule_id for h in hits]
        assert "METADATA_STRIP" in rule_ids

    def test_score_normalised(self, engine) -> None:
        """Score must always be in [0, 1]."""
        activity = {
            "file_classifier": "ts_sci",
            "user_max_clearance": "open",
            "access_novelty_score": 10.0,
            "off_hours_multiplier": 5.0,
            "access_hour": 2,
            "metadata_stripped": True,
            "followed_by_outbound": True,
            "outbound_gap_minutes": 10,
            "copy_to_removable": True,
            "badge_gap_minutes": 5,
        }
        score, _ = engine.evaluate(activity)
        assert 0.0 <= score <= 1.0


# ── ISO 27043 ─────────────────────────────────────────────────────────────

class TestISO27043:
    def test_coverage_above_90_pct(self) -> None:
        from turret_evidence.iso27043 import ISO27043Checker
        from turret_common.schemas import DetectionAlert
        from uuid import uuid4
        from datetime import datetime, timezone

        alert = DetectionAlert(
            alert_id=uuid4(),
            user_uid="U00001",
            window_start=datetime.now(tz=timezone.utc),
            window_end=datetime.now(tz=timezone.utc),
            score=0.85,
            contributing_rules=[],
            subgraph_nodes=[{"node_id": "N1", "node_type": "User", "label": "U00001"}],
            subgraph_edges=[],
            shap_values={"CLEARANCE_VIOLATION": 0.3},
        )
        checker = ISO27043Checker()
        attrs = checker.check(alert)
        coverage = checker.coverage_pct(attrs)
        assert coverage >= 90.0, f"ISO 27043 coverage {coverage:.1f}% < 90%"
