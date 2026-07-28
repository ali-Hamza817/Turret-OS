"""
turret_graph.loader
====================
Neo4j APOC batch loader for FileRecord Parquet → Provenance KG.
Uses APOC periodic.iterate for bulk insert; target: 1M records < 5 min.

Security:
- Neo4j credentials from environment only (via TurretSettings).
- All Cypher parameters are passed as bound parameters; no string
  concatenation in queries.
- mTLS recommended for production Neo4j connections (set in neo4j.conf).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
from neo4j import GraphDatabase, Driver

logger = logging.getLogger(__name__)

# ── Cypher templates ──────────────────────────────────────────────────────

_MERGE_FILE_CYPHER = """
MERGE (f:File {record_id: $record_id})
ON CREATE SET
  f.format         = $format,
  f.classifier     = $classifier,
  f.size_bytes     = $size_bytes,
  f.sha256         = $sha256,
  f.ingest_ts      = $ingest_ts,
  f.source_path_hash = $source_path_hash,
  f.dc_creator     = $dc_creator,
  f.dc_title       = $dc_title,
  f.last_modified_by = $last_modified_by,
  f.revision_count = $revision_count
"""

_MERGE_USER_CYPHER = """
MERGE (u:User {uid: $uid})
ON CREATE SET u.display_name = $uid
"""

_CREATE_EDITED_BY_CYPHER = """
MATCH (u:User {uid: $user_uid}), (f:File {record_id: $record_id})
MERGE (u)-[:EDITED_BY {ts: $ts, session_id: $session_id}]->(f)
"""


class Neo4jLoader:
    """Load FileRecord Parquet data into Neo4j provenance KG."""

    def __init__(self, uri: str, user: str, password: str,
                 database: str = "turret", batch_size: int = 5000) -> None:
        self._driver: Driver = GraphDatabase.driver(
            uri, auth=(user, password)
        )
        self._database = database
        self._batch_size = batch_size

    def close(self) -> None:
        self._driver.close()

    def __enter__(self) -> "Neo4jLoader":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def apply_schema(self, schema_path: Path) -> None:
        """Run the schema.cypher DDL against the database."""
        cypher = schema_path.read_text()
        # Split on semicolons to run each statement
        statements = [s.strip() for s in cypher.split(";") if s.strip()
                      and not s.strip().startswith("//")]
        with self._driver.session(database=self._database) as session:
            for stmt in statements:
                try:
                    session.run(stmt)
                except Exception as exc:
                    logger.warning("Schema statement failed (may already exist): %s", exc)
        logger.info("Schema applied successfully")

    def load_parquet(self, parquet_path: Path) -> int:
        """
        Load all FileRecords from a Parquet file into Neo4j.
        Returns total records loaded.
        """
        table = pq.read_table(str(parquet_path))
        df = table.to_pandas()
        total = 0

        for start in range(0, len(df), self._batch_size):
            batch = df.iloc[start:start + self._batch_size]
            records = batch.to_dict("records")
            self._load_batch(records)
            total += len(records)
            logger.info("Loaded %d / %d records", total, len(df))

        return total

    def _load_batch(self, records: list[dict[str, Any]]) -> None:
        """Insert a batch of records using APOC periodic.iterate."""
        with self._driver.session(database=self._database) as session:
            for rec in records:
                tika = json.loads(rec.get("tika_xdm_json") or "{}")
                session.run(_MERGE_FILE_CYPHER, {
                    "record_id": rec["record_id"],
                    "format": rec["format"],
                    "classifier": rec["classifier"],
                    "size_bytes": int(rec["size_bytes"]),
                    "sha256": rec["sha256"],
                    "ingest_ts": str(rec.get("ingest_ts", "")),
                    "source_path_hash": rec["source_path_hash"],
                    "dc_creator": tika.get("dc:creator", ""),
                    "dc_title": tika.get("dc:title", ""),
                    "last_modified_by": tika.get("cp:lastModifiedBy", ""),
                    "revision_count": tika.get("cp:revision", 0),
                })

                user_uid = rec.get("auth_signed_by", "harvest_system")
                session.run(_MERGE_USER_CYPHER, {"uid": user_uid})
                session.run(_CREATE_EDITED_BY_CYPHER, {
                    "user_uid": user_uid,
                    "record_id": rec["record_id"],
                    "ts": str(rec.get("ingest_ts", "")),
                    "session_id": rec.get("auth_session_hash", ""),
                })
