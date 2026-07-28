"""
turret_harvest.parsers.eml_parser
===================================
Email (.eml, .msg) metadata extractor.
Extracts: sender, recipients, CC/BCC, subject, message-id, X-Mailer,
date, attachment names and sizes, and MIME structure.

Security:
- Uses Python stdlib email.parser (no arbitrary exec).
- Attachment filenames are extracted as metadata only; never written to disk.
- Email bodies are not parsed for content; only headers + structure.
"""

from __future__ import annotations

import email
import email.policy
import logging
from pathlib import Path
from typing import Any

from turret_harvest.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class EmlParser(BaseParser):
    """Extract metadata from .eml email files."""

    SUPPORTED_FORMATS = frozenset({"eml", "msg"})

    def extract(self, path: Path) -> dict[str, Any]:
        try:
            return self._parse_eml(path)
        except Exception as exc:
            logger.warning("EML parse failure on %s: %s", path.name, exc)
            return {"tika_xdm": {}, "exif": None, "custom": {"parse_error": str(exc)}}

    def _parse_eml(self, path: Path) -> dict[str, Any]:
        content = path.read_bytes()
        msg = email.message_from_bytes(content, policy=email.policy.default)

        tika_xdm = {
            "dc:creator": msg.get("From", ""),
            "dc:title": msg.get("Subject", ""),
            "cp:created": msg.get("Date", ""),
            "msg:message-id": msg.get("Message-ID", ""),
            "msg:x-mailer": msg.get("X-Mailer", ""),
            "msg:user-agent": msg.get("User-Agent", ""),
        }

        recipients = self._parse_addresses(msg.get("To", ""))
        cc = self._parse_addresses(msg.get("CC", ""))
        bcc = self._parse_addresses(msg.get("BCC", ""))

        attachments: list[dict[str, Any]] = []
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename() or "unnamed"
                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0
                attachments.append({
                    "filename": filename,
                    "mime_type": part.get_content_type(),
                    "size_bytes": size,
                })

        custom = {
            "recipients": recipients,
            "cc": cc,
            "bcc": bcc,
            "recipient_count": len(recipients) + len(cc) + len(bcc),
            "has_external_recipients": self._has_external(recipients + cc + bcc),
            "attachments": attachments,
            "attachment_count": len(attachments),
            "total_attachment_bytes": sum(a["size_bytes"] for a in attachments),
        }

        return {"tika_xdm": tika_xdm, "exif": None, "custom": custom}

    @staticmethod
    def _parse_addresses(header_value: str) -> list[str]:
        if not header_value:
            return []
        return [addr.strip() for addr in header_value.split(",") if addr.strip()]

    @staticmethod
    def _has_external(addresses: list[str]) -> bool:
        """Heuristic: any address not on a known internal domain."""
        # Placeholder: in production, compare against org domain list from config
        return len(addresses) > 0
