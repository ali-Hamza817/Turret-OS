"""
turret_harvest.parsers.base
===========================
Abstract base parser that all format-specific parsers must subclass.
Enforces a uniform interface so the harvest orchestrator can call any
parser identically.
"""

from __future__ import annotations

import abc
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class BaseParser(abc.ABC):
    """
    Abstract metadata parser.

    Each concrete parser is responsible for:
    - Declaring which file formats it handles (``SUPPORTED_FORMATS``)
    - Extracting a dict of metadata fields from a file path
    - Raising ``ParseError`` on unrecoverable failures

    Security notes:
    - Path is validated by the caller (``HarvestOrchestrator``) before
      being passed here; parsers MUST NOT perform additional path resolution.
    - Parsers MUST NOT execute shell commands with un-sanitised input.
    - External tools (ExifTool, Tika) are called with a hardcoded binary
      path from config; never from user-supplied input.
    """

    #: File format strings this parser handles (matches FileRecord.format)
    SUPPORTED_FORMATS: frozenset[str] = frozenset()

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = config or {}

    @abc.abstractmethod
    def extract(self, path: Path) -> dict[str, Any]:
        """
        Extract metadata from *path*.

        Returns a dict containing at minimum:
        - ``tika_xdm``: dict (may be empty)
        - ``exif``: dict | None
        - ``custom``: dict of format-specific fields

        Must not raise on partial failures; log and return partial data.
        """
        ...

    def supports(self, suffix: str) -> bool:
        """Return True if this parser handles the given file extension."""
        return suffix.lower().lstrip(".") in self.SUPPORTED_FORMATS


class ParseError(Exception):
    """Raised when a parser cannot recover from a malformed file."""
