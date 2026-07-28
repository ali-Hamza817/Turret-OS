"""
turret_harvest.orchestrator
============================
HarvestOrchestrator — coordinates all format-specific parsers,
validates input paths, assigns FileRecord metadata, and routes output
to the ParquetSink.

Security:
- Input paths are resolved to absolute paths and checked to be within
  the allowed source root before any parser is invoked.
- File sizes are checked against MAX_FILE_SIZE_MB before parsing.
- Symlinks are followed only if they resolve within the source root.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from turret_common.hashing import sha256_file, blake3_file, sha256_path
from turret_harvest.parsers.base import BaseParser
from turret_harvest.parsers.docx_parser import DocxParser
from turret_harvest.parsers.pdf_parser import PdfParser
from turret_harvest.parsers.image_parser import ImageParser
from turret_harvest.parsers.eml_parser import EmlParser
from turret_harvest.parsers.git_parser import GitParser
from turret_harvest.sink import ParquetSink

logger = logging.getLogger(__name__)

MAX_FILE_SIZE_MB = 512

# Extension → format string (FileRecord.format)
EXT_TO_FORMAT: dict[str, str] = {
    "docx": "docx", "xlsx": "xlsx", "pptx": "pptx",
    "pdf": "pdf",
    "dwg": "dwg",
    "eml": "eml", "msg": "eml",
    "jpg": "jpeg", "jpeg": "jpeg",
    "png": "png",
    "tiff": "tiff", "tif": "tiff",
}


class HarvestOrchestrator:
    """
    Orchestrate metadata harvest across a source directory.
    """

    def __init__(self, source_root: Path, config: dict[str, Any]) -> None:
        self.source_root = source_root.resolve()
        self.config = config
        self._parsers: list[BaseParser] = [
            DocxParser(config),
            PdfParser(config),
            ImageParser(config),
            EmlParser(config),
            GitParser(config),
        ]

    def harvest(self, sink: ParquetSink, classifier: str = "open") -> int:
        """
        Walk source_root, parse all supported files, and write to sink.
        Returns the number of records harvested.
        """
        count = 0
        for file_path in self._iter_files():
            try:
                record = self._process_file(file_path, classifier)
                if record:
                    sink.write(record)
                    count += 1
            except Exception as exc:
                logger.error("Failed to process %s: %s", file_path.name, exc)
        logger.info("Harvested %d records from %s", count, self.source_root)
        return count

    def _iter_files(self):
        """Yield all files under source_root, skipping oversized files."""
        max_bytes = MAX_FILE_SIZE_MB * 1024 * 1024
        for path in self.source_root.rglob("*"):
            if not path.is_file():
                continue
            # Security: resolve and verify within source_root
            resolved = path.resolve()
            if not str(resolved).startswith(str(self.source_root) + "/"):
                logger.warning("Path traversal attempt blocked: %s", path)
                continue
            if path.stat().st_size > max_bytes:
                logger.info("Skipping oversized file: %s (%d bytes)", path.name, path.stat().st_size)
                continue
            yield path

    def _process_file(self, path: Path, classifier: str) -> dict[str, Any] | None:
        fmt = EXT_TO_FORMAT.get(path.suffix.lower().lstrip("."))
        if not fmt:
            return None

        parser = self._find_parser(fmt)
        if not parser:
            logger.debug("No parser for format %s (%s)", fmt, path.name)
            return None

        extracted = parser.extract(path)

        return {
            "record_id": uuid.uuid4(),
            "ingest_ts": datetime.now(tz=timezone.utc),
            "source_path_hash": sha256_path(path),
            "format": fmt,
            "size_bytes": path.stat().st_size,
            "classifier": classifier,
            "tika_xdm": extracted.get("tika_xdm", {}),
            "exif": extracted.get("exif"),
            "custom": extracted.get("custom", {}),
            "auth_chain": {
                "signed_by_user": "harvest_system",
                "delegated_as": [],
                "session_token_hash": "0" * 64,
                "device_id": None,
            },
            "hashes": {
                "sha256": sha256_file(path),
                "blake3": blake3_file(path),
            },
        }

    def _find_parser(self, fmt: str) -> BaseParser | None:
        for p in self._parsers:
            if fmt in p.SUPPORTED_FORMATS:
                return p
        return None
