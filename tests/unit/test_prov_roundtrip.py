"""
tests/unit/test_prov_roundtrip.py
==================================
W3C PROV-JSON-LD round-trip serialization and schema verification tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from turret_graph.prov_serializer import ProvSerializer


def test_prov_jsonld_roundtrip(tmp_path: Path) -> None:
    """Verify that PROV-JSON-LD serializes and deserializes cleanly with valid context."""
    serializer = ProvSerializer()

    edges = [
        {
            "src": {"node_id": "U001", "node_type": "User", "label": "User U001"},
            "dst": {"node_id": "F001", "node_type": "File", "label": "Doc.docx"},
            "type": "EDITED_BY",
            "ts": "2026-07-28T08:00:00Z",
        },
        {
            "src": {"node_id": "F001", "node_type": "File", "label": "Doc.docx"},
            "dst": {"node_id": "C001", "node_type": "Channel", "label": "Email"},
            "type": "EMAILED_TO",
            "ts": "2026-07-28T08:05:00Z",
            "client_app": "Outlook",
        },
    ]

    out_file = tmp_path / "prov.jsonld"
    doc = serializer.serialize(edges, alert_id="ALT-12345", output_path=out_file)

    assert out_file.exists()

    # Re-read and parse JSON
    read_doc = json.loads(out_file.read_text())

    assert read_doc["@id"] == "turret:alert_ALT-12345"
    assert "@context" in read_doc
    assert "prov:entity" in read_doc
    assert "prov:agent" in read_doc
    assert len(read_doc["turret:relations"]) == 2
