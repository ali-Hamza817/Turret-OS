"""
turret_harvest.parsers.pdf_parser
==================================
PDF metadata extractor using pikepdf + Apache Tika.
Extracts: XMP metadata, document information dictionary, embedded
author strings, creation/modification timestamps, and producer strings.

Security:
- pikepdf is used for structured PDF parsing (not exec-based).
- Tika is called via its Python SDK against a pre-started server; the
  server JAR path is from config only (never user input).
- TODO(security): Add PDF CDR (content disarm and reconstruction) step
  to strip JavaScript and embedded executable content before analysis.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from turret_harvest.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class PdfParser(BaseParser):
    """Extract metadata from PDF files using pikepdf and Tika."""

    SUPPORTED_FORMATS = frozenset({"pdf"})

    def extract(self, path: Path) -> dict[str, Any]:
        tika_xdm: dict[str, Any] = {}
        custom: dict[str, Any] = {}

        # ── pikepdf structured extraction ──────────────────────────────────
        try:
            import pikepdf  # type: ignore[import]

            with pikepdf.open(str(path)) as pdf:
                info = pdf.docinfo
                tika_xdm.update({
                    "dc:creator": str(info.get("/Author", "")),
                    "dc:title": str(info.get("/Title", "")),
                    "dc:subject": str(info.get("/Subject", "")),
                    "cp:created": str(info.get("/CreationDate", "")),
                    "cp:modified": str(info.get("/ModDate", "")),
                    "pdf:producer": str(info.get("/Producer", "")),
                    "pdf:creator_tool": str(info.get("/Creator", "")),
                })

                # XMP metadata (richer source)
                try:
                    with pdf.open_metadata() as meta:
                        xmp_meta = dict(meta)
                        tika_xdm.update({k: str(v) for k, v in xmp_meta.items()})
                except Exception as e:
                    logger.debug("XMP read failed: %s", e)

                custom["page_count"] = len(pdf.pages)
                custom["is_encrypted"] = pdf.is_encrypted
                custom["pdf_version"] = pdf.pdf_version

        except Exception as exc:
            logger.warning("pikepdf extraction failed on %s: %s", path.name, exc)
            custom["pikepdf_error"] = str(exc)

        # ── Apache Tika extraction ─────────────────────────────────────────
        try:
            from tika import parser as tika_parser  # type: ignore[import]
            parsed = tika_parser.from_file(str(path))
            if parsed and parsed.get("metadata"):
                tika_meta = parsed["metadata"]
                # Merge Tika metadata; don't overwrite pikepdf values
                for k, v in tika_meta.items():
                    if k not in tika_xdm:
                        tika_xdm[k] = v[0] if isinstance(v, list) else v
        except Exception as exc:
            logger.debug("Tika extraction failed on %s: %s", path.name, exc)
            custom["tika_error"] = str(exc)

        return {"tika_xdm": tika_xdm, "exif": None, "custom": custom}
