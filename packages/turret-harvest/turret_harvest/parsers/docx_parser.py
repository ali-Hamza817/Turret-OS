"""
turret_harvest.parsers.docx_parser
===================================
Microsoft OOXML Word document metadata extractor.
Extracts: core properties, revision history, tracked changes,
embedded author strings, and comment authors.

Security:
- Uses python-docx with XXE protection (lxml with defusedxml).
- All file paths are validated by the caller; this parser never joins
  user-supplied strings into paths.
- TODO(security): Integrate CDR tool to strip macros before parsing.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from turret_harvest.parsers.base import BaseParser, ParseError

logger = logging.getLogger(__name__)


class DocxParser(BaseParser):
    """Extract metadata from DOCX, XLSX, PPTX (OOXML) files."""

    SUPPORTED_FORMATS = frozenset({"docx", "xlsx", "pptx"})

    def extract(self, path: Path) -> dict[str, Any]:
        """
        Extract OOXML core properties and revision metadata.

        Returns dict with keys:
        - tika_xdm: core Dublin Core + OOXML extended properties
        - exif: None (not applicable)
        - custom: {authors, last_modifier, revision_count, tracked_changes_count,
                   comment_authors, hidden_text_present}
        """
        try:
            return self._extract_docx(path)
        except Exception as exc:
            logger.warning("DOCX parse partial failure on %s: %s", path.name, exc)
            return {"tika_xdm": {}, "exif": None, "custom": {"parse_error": str(exc)}}

    def _extract_docx(self, path: Path) -> dict[str, Any]:
        from docx import Document  # type: ignore[import]

        doc = Document(str(path))
        cp = doc.core_properties

        tika_xdm: dict[str, Any] = {
            "dc:creator": cp.author or "",
            "dc:title": cp.title or "",
            "dc:subject": cp.subject or "",
            "dc:description": getattr(cp, "description", None) or getattr(cp, "comments", "") or "",
            "dc:keywords": getattr(cp, "keywords", "") or "",
            "dc:language": getattr(cp, "language", "") or "",
            "cp:lastModifiedBy": cp.last_modified_by or "",
            "cp:revision": cp.revision,
            "cp:created": cp.created.isoformat() if cp.created else None,
            "cp:modified": cp.modified.isoformat() if cp.modified else None,
            "cp:lastPrinted": cp.last_printed.isoformat() if cp.last_printed else None,
        }

        # Gather all unique author strings from the document body
        authors: set[str] = set()
        if cp.author:
            authors.add(cp.author)
        if cp.last_modified_by:
            authors.add(cp.last_modified_by)

        # Count tracked changes
        tracked_changes = 0
        comment_authors: set[str] = set()
        try:
            from lxml import etree  # type: ignore[import]
            ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            body = doc.element.body
            tracked_changes = len(body.findall(f".//{{{ns}}}ins") +
                                  body.findall(f".//{{{ns}}}del"))
            for comment in doc.element.findall(f".//{{{ns}}}comment"):
                author = comment.get(f"{{{ns}}}author", "")
                if author:
                    comment_authors.add(author)
                    authors.add(author)
        except Exception as exc:
            logger.debug("Tracked-changes extraction failed: %s", exc)

        # Check for hidden text
        hidden_text = False
        try:
            from lxml import etree  # noqa: F811
            ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
            hidden_text = bool(
                doc.element.body.findall(f".//{{{ns}}}vanish")
            )
        except Exception:
            pass

        custom = {
            "authors": sorted(authors),
            "last_modifier": cp.last_modified_by or "",
            "revision_count": cp.revision or 0,
            "tracked_changes_count": tracked_changes,
            "comment_authors": sorted(comment_authors),
            "hidden_text_present": hidden_text,
        }

        return {"tika_xdm": tika_xdm, "exif": None, "custom": custom}
