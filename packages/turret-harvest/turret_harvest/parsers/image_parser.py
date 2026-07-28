"""
turret_harvest.parsers.image_parser
=====================================
JPEG / PNG / TIFF metadata extractor.
Uses ExifTool (subprocess with hardcoded binary path from config) and
Pillow for EXIF / IPTC / XMP extraction.

Security:
- ExifTool binary path comes from config only; never from user input.
- subprocess.run is called with a hardcoded arg list; no shell=True.
- File path is validated (Path object, within allowed root) before call.
- GPS coordinates extracted and stored; can be used as exfiltration
  indicator if cleared documents carry location metadata.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from turret_harvest.parsers.base import BaseParser

logger = logging.getLogger(__name__)

# Hardcoded allowed arguments for ExifTool; no user input allowed here
_EXIFTOOL_ARGS = ["-json", "-struct", "-n", "-charset", "UTF8"]


class ImageParser(BaseParser):
    """Extract EXIF/IPTC/XMP metadata from JPEG, PNG, and TIFF files."""

    SUPPORTED_FORMATS = frozenset({"jpeg", "jpg", "png", "tiff", "tif"})

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._exiftool_path: str = (config or {}).get("exiftool", {}).get(
            "path", "/usr/bin/exiftool"
        )

    def extract(self, path: Path) -> dict[str, Any]:
        exif = self._run_exiftool(path)
        tika_xdm = self._tika_extract(path)
        custom = self._extract_custom_fields(exif)
        return {"tika_xdm": tika_xdm, "exif": exif, "custom": custom}

    def _run_exiftool(self, path: Path) -> dict[str, Any]:
        """
        Run ExifTool with a strictly controlled argument list.
        Security: binary path from config only; args hardcoded; shell=False.
        """
        try:
            cmd = [self._exiftool_path] + _EXIFTOOL_ARGS + [str(path)]
            result = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,  # MUST be False; never pass shell=True with file paths
            )
            if result.returncode != 0:
                logger.warning("ExifTool non-zero exit for %s: %s", path.name, result.stderr)
                return {}
            parsed = json.loads(result.stdout)
            return parsed[0] if parsed else {}
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning("ExifTool unavailable or timed out: %s", exc)
            return {}
        except json.JSONDecodeError as exc:
            logger.warning("ExifTool JSON decode error for %s: %s", path.name, exc)
            return {}

    def _tika_extract(self, path: Path) -> dict[str, Any]:
        try:
            from tika import parser as tika_parser  # type: ignore[import]
            parsed = tika_parser.from_file(str(path))
            if parsed and parsed.get("metadata"):
                meta = parsed["metadata"]
                return {k: (v[0] if isinstance(v, list) else v) for k, v in meta.items()}
        except Exception as exc:
            logger.debug("Tika image extraction failed: %s", exc)
        return {}

    def _extract_custom_fields(self, exif: dict[str, Any]) -> dict[str, Any]:
        """Derive high-value forensic fields from raw EXIF data."""
        custom: dict[str, Any] = {}

        # GPS presence is a strong exfiltration indicator for classified docs
        custom["has_gps"] = "GPSLatitude" in exif or "GPSLongitude" in exif
        if custom["has_gps"]:
            custom["gps_lat"] = exif.get("GPSLatitude")
            custom["gps_lon"] = exif.get("GPSLongitude")
            custom["gps_alt"] = exif.get("GPSAltitude")

        custom["camera_make"] = exif.get("Make", "")
        custom["camera_model"] = exif.get("Model", "")
        custom["software"] = exif.get("Software", "")
        custom["date_time_original"] = exif.get("DateTimeOriginal", "")
        custom["modify_date"] = exif.get("ModifyDate", "")
        custom["create_date"] = exif.get("CreateDate", "")
        custom["author"] = exif.get("Artist") or exif.get("By-line", "")

        # Detect stripped metadata (all key fields None)
        key_fields = ["Make", "Model", "DateTimeOriginal", "Software", "Artist"]
        custom["metadata_stripped"] = all(exif.get(f) is None for f in key_fields)

        return custom
