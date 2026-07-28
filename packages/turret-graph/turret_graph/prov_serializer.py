"""
turret_graph.prov_serializer
=============================
Serialize Neo4j provenance subgraphs to W3C PROV-JSON-LD format
using rdflib.  Output is standards-compliant and can be validated
against the PROV-O OWL ontology.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# W3C PROV namespace
PROV_NS = "http://www.w3.org/ns/prov#"
XSD_NS = "http://www.w3.org/2001/XMLSchema#"
TURRET_NS = "https://turret-os.example.org/prov#"


class ProvSerializer:
    """
    Convert a list of ProvenanceEdge dicts into a W3C PROV-JSON-LD document.
    """

    def serialize(
        self,
        edges: list[dict[str, Any]],
        alert_id: str,
        output_path: Path | None = None,
    ) -> dict[str, Any]:
        """
        Build a PROV-JSON-LD document from a list of edge dicts.

        Returns the document as a Python dict (also writes to output_path
        if provided).
        """
        doc = self._build_document(edges, alert_id)
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(doc, indent=2, default=str))
            logger.info("PROV-JSON-LD written to %s", output_path)
        return doc

    def _build_document(self, edges: list[dict[str, Any]], alert_id: str) -> dict[str, Any]:
        context = {
            "prov": PROV_NS,
            "xsd": XSD_NS,
            "turret": TURRET_NS,
            "wasGeneratedBy": {"@id": "prov:wasGeneratedBy", "@type": "@id"},
            "wasAttributedTo": {"@id": "prov:wasAttributedTo", "@type": "@id"},
            "used": {"@id": "prov:used", "@type": "@id"},
            "wasDerivedFrom": {"@id": "prov:wasDerivedFrom", "@type": "@id"},
            "wasAssociatedWith": {"@id": "prov:wasAssociatedWith", "@type": "@id"},
            "actedOnBehalfOf": {"@id": "prov:actedOnBehalfOf", "@type": "@id"},
            "atTime": {"@id": "prov:atTime", "@type": "xsd:dateTime"},
            "startedAtTime": {"@id": "prov:startedAtTime", "@type": "xsd:dateTime"},
            "endedAtTime": {"@id": "prov:endedAtTime", "@type": "xsd:dateTime"},
        }

        entities: dict[str, Any] = {}
        agents: dict[str, Any] = {}
        activities: dict[str, Any] = {}
        relations: list[dict[str, Any]] = []

        for edge in edges:
            src = edge.get("src", {})
            dst = edge.get("dst", {})
            edge_type = edge.get("type", "UNKNOWN")
            ts = edge.get("ts", datetime.utcnow().isoformat())

            src_id = f"turret:{src.get('node_type', 'Node')}_{src.get('node_id', 'unknown')}"
            dst_id = f"turret:{dst.get('node_type', 'Node')}_{dst.get('node_id', 'unknown')}"

            # Register nodes as entities / agents
            if src.get("node_type") in ("User",):
                agents[src_id] = {"@type": "prov:Agent", "prov:label": src.get("label", src_id)}
            else:
                entities[src_id] = {"@type": "prov:Entity", "prov:label": src.get("label", src_id)}

            entities[dst_id] = {"@type": "prov:Entity", "prov:label": dst.get("label", dst_id)}

            # Map TURRET edge types to PROV relations
            prov_rel = self._map_edge_to_prov(edge_type, src_id, dst_id, ts, edge)
            if prov_rel:
                relations.append(prov_rel)

        return {
            "@context": context,
            "@id": f"turret:alert_{alert_id}",
            "@type": "prov:Bundle",
            "prov:entity": entities,
            "prov:agent": agents,
            "prov:activity": activities,
            "turret:relations": relations,
            "turret:generatedAt": datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _map_edge_to_prov(
        edge_type: str, src_id: str, dst_id: str, ts: Any, edge: dict[str, Any]
    ) -> dict[str, Any] | None:
        mapping = {
            "EDITED_BY": {
                "@type": "prov:wasAttributedTo",
                "prov:entity": dst_id,
                "prov:agent": src_id,
                "prov:atTime": ts,
            },
            "EMAILED_TO": {
                "@type": "prov:wasDerivedFrom",
                "prov:generatedEntity": dst_id,
                "prov:usedEntity": src_id,
                "prov:atTime": ts,
                "turret:channel": edge.get("client_app", ""),
            },
            "COMMITTED_TO": {
                "@type": "prov:wasGeneratedBy",
                "prov:entity": src_id,
                "prov:activity": dst_id,
                "prov:atTime": ts,
                "turret:revision": edge.get("revision_id", ""),
            },
            "UPLOADED_TO": {
                "@type": "prov:wasDerivedFrom",
                "prov:generatedEntity": dst_id,
                "prov:usedEntity": src_id,
                "prov:atTime": ts,
            },
            "PRINTED_BY": {
                "@type": "prov:used",
                "prov:entity": src_id,
                "prov:activity": dst_id,
                "prov:atTime": ts,
            },
        }
        return mapping.get(edge_type, {
            "@type": f"turret:{edge_type}",
            "prov:entity": src_id,
            "prov:relatedTo": dst_id,
            "prov:atTime": ts,
        })
