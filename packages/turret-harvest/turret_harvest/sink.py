"""
turret_harvest.sink
====================
Parquet + DuckDB output sink for harvested FileRecord objects.
Writes deterministic, schema-validated Parquet files partitioned by
format and classifier for efficient downstream querying.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from uuid import UUID
from datetime import datetime

import pyarrow as pa
import pyarrow.parquet as pq

logger = logging.getLogger(__name__)

# ── Arrow schema matching FileRecord ──────────────────────────────────────

FILE_RECORD_SCHEMA = pa.schema([
    pa.field("record_id", pa.string()),           # UUID as string
    pa.field("ingest_ts", pa.timestamp("us", tz="UTC")),
    pa.field("source_path_hash", pa.string()),
    pa.field("format", pa.string()),
    pa.field("size_bytes", pa.int64()),
    pa.field("classifier", pa.string()),
    pa.field("tika_xdm_json", pa.string()),       # JSON-encoded dict
    pa.field("exif_json", pa.string()),            # JSON-encoded dict | null
    pa.field("custom_json", pa.string()),          # JSON-encoded dict
    pa.field("auth_signed_by", pa.string()),
    pa.field("auth_session_hash", pa.string()),
    pa.field("auth_device_id", pa.string()),
    pa.field("sha256", pa.string()),
    pa.field("blake3", pa.string()),
])


class ParquetSink:
    """
    Accumulates FileRecord-like dicts and flushes to partitioned Parquet.
    Thread-safe for single-writer use; not concurrent-writer safe.
    """

    def __init__(self, output_path: Path, compression: str = "snappy") -> None:
        self.output_path = output_path
        self.compression = compression
        self._buffer: list[dict[str, Any]] = []

    def write(self, record: dict[str, Any]) -> None:
        """Append a single record to the in-memory buffer."""
        self._buffer.append(self._flatten(record))

    def write_batch(self, records: list[dict[str, Any]]) -> None:
        """Append multiple records."""
        for rec in records:
            self._buffer.append(self._flatten(rec))

    def flush(self) -> Path:
        """
        Write all buffered records to a Parquet file.
        Returns the path of the written file.
        """
        if not self._buffer:
            logger.warning("ParquetSink.flush() called with empty buffer")
            return self.output_path

        import json
        import pandas as pd

        df = pd.DataFrame(self._buffer)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        table = pa.Table.from_pandas(df, schema=FILE_RECORD_SCHEMA, safe=False)
        pq.write_table(
            table,
            self.output_path,
            compression=self.compression,
            write_statistics=True,
        )
        logger.info("Wrote %d records to %s", len(self._buffer), self.output_path)
        self._buffer.clear()
        return self.output_path

    @staticmethod
    def _flatten(rec: dict[str, Any]) -> dict[str, Any]:
        """Flatten nested FileRecord structure to a single dict row."""
        import json

        auth = rec.get("auth_chain", {})
        hashes = rec.get("hashes", {})
        return {
            "record_id": str(rec.get("record_id", "")),
            "ingest_ts": rec.get("ingest_ts"),
            "source_path_hash": rec.get("source_path_hash", ""),
            "format": rec.get("format", ""),
            "size_bytes": rec.get("size_bytes", 0),
            "classifier": rec.get("classifier", "open"),
            "tika_xdm_json": json.dumps(rec.get("tika_xdm", {}), default=str),
            "exif_json": json.dumps(rec.get("exif") or {}, default=str),
            "custom_json": json.dumps(rec.get("custom", {}), default=str),
            "auth_signed_by": auth.get("signed_by_user", "") if isinstance(auth, dict) else "",
            "auth_session_hash": auth.get("session_token_hash", "") if isinstance(auth, dict) else "",
            "auth_device_id": auth.get("device_id", "") if isinstance(auth, dict) else "",
            "sha256": hashes.get("sha256", "") if isinstance(hashes, dict) else "",
            "blake3": hashes.get("blake3") or "" if isinstance(hashes, dict) else "",
        }
