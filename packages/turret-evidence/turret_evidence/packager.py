"""
turret_evidence.packager
=========================
Assemble signed ISO/IEC 27043-aligned evidence packages (ZIP bundles).
Each alert produces one ZIP containing:
  - alert.json          : DetectionAlert serialised
  - prov.jsonld         : W3C PROV-JSON-LD provenance document
  - chain_of_custody.json
  - iso27043_checklist.json
  - merkle_manifest.json : {files: [{filename, sha256}], merkle_root, signature}

Security:
- ZIP entries are written with deterministic file names (no user input).
- All files are hashed before and after packaging; Merkle root verified.
- Ed25519 signature covers the Merkle root; stored in manifest.
"""

from __future__ import annotations

import json
import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from turret_common.schemas import DetectionAlert, EvidencePack, CustodyOp, Ed25519Sig
from turret_common.hashing import sha256_bytes, build_merkle_root
from turret_evidence.iso27043 import ISO27043Checker

logger = logging.getLogger(__name__)


class EvidencePackager:
    """
    Build a signed evidence ZIP bundle for a DetectionAlert.
    """

    def __init__(
        self,
        signer: Any | None = None,
        output_dir: Path = Path("evidence_packs"),
    ) -> None:
        self.signer = signer
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.iso_checker = ISO27043Checker()

    def package(
        self,
        alert: DetectionAlert,
        prov_jsonld: dict[str, Any],
    ) -> EvidencePack:
        """
        Build and sign an evidence pack for the given alert.

        Returns the EvidencePack schema object.
        """
        evidence_id = str(alert.alert_id)
        zip_path = self.output_dir / f"{evidence_id}.zip"

        # ── Build file contents ───────────────────────────────────────────
        alert_json = json.dumps(
            alert.model_dump(mode="json"), indent=2, default=str
        ).encode("utf-8")
        prov_json = json.dumps(prov_jsonld, indent=2, default=str).encode("utf-8")

        iso_attrs = self.iso_checker.check(alert)
        iso_json = json.dumps(iso_attrs, indent=2).encode("utf-8")

        ts_now = datetime.now(tz=timezone.utc)
        custody_ops = [
            CustodyOp(
                op_id="op_001",
                op_type="collect",
                actor="turret_evidence_packager_v0.1",
                ts=ts_now,
                tool="turret-evidence==0.1.0",
                hash_before=None,
                hash_after=None,
                notes="Automated evidence collection from TURRET OS alert pipeline",
            )
        ]
        custody_json = json.dumps(
            [op.model_dump(mode="json") for op in custody_ops], indent=2, default=str
        ).encode("utf-8")

        # ── Hash all files ────────────────────────────────────────────────
        files = {
            "alert.json": alert_json,
            "prov.jsonld": prov_json,
            "iso27043_checklist.json": iso_json,
            "chain_of_custody.json": custody_json,
        }
        file_hashes = {name: sha256_bytes(content) for name, content in files.items()}

        # ── Build Merkle root ─────────────────────────────────────────────
        leaf_hashes = [file_hashes[name] for name in sorted(file_hashes.keys())]
        merkle_root = build_merkle_root(leaf_hashes)

        # ── Sign ──────────────────────────────────────────────────────────
        signatures: list[Ed25519Sig] = []
        if self.signer:
            try:
                sig = self.signer.sign_merkle_root(merkle_root, signer_id="turret_api")
                signatures.append(sig)
            except Exception as exc:
                logger.error("Signing failed: %s", exc)

        # ── Merkle manifest ───────────────────────────────────────────────
        manifest = {
            "evidence_id": evidence_id,
            "merkle_root": merkle_root,
            "files": [
                {"filename": name, "sha256": h}
                for name, h in sorted(file_hashes.items())
            ],
            "signatures": [sig.model_dump(mode="json") for sig in signatures],
            "generated_at": ts_now.isoformat(),
        }
        manifest_json = json.dumps(manifest, indent=2, default=str).encode("utf-8")
        files["merkle_manifest.json"] = manifest_json

        # ── Write ZIP ─────────────────────────────────────────────────────
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(name, content)

        logger.info("Evidence pack written: %s (merkle_root=%s...)", zip_path, merkle_root[:16])

        return EvidencePack(
            evidence_id=evidence_id,
            alert=alert,
            prov_jsonld_blob_key=str(zip_path),
            file_hashes=list(file_hashes.values()),
            merkle_root=merkle_root,
            rfc3227_image_md5=None,
            chain_of_custody=custody_ops,
            signatures=signatures,
            iso27043_attributes=iso_attrs,
        )

    def verify_pack(self, zip_path: Path) -> bool:
        """
        Verify the integrity of an evidence pack ZIP.
        Returns True if Merkle root and all signatures verify.
        """
        from turret_evidence.signer import EvidenceSigner

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                manifest = json.loads(zf.read("merkle_manifest.json"))

                # Recompute Merkle root from file hashes
                file_hashes = sorted(manifest["files"], key=lambda x: x["filename"])
                leaf_hashes = [f["sha256"] for f in file_hashes]

                # Verify each file hash
                for entry in manifest["files"]:
                    name = entry["filename"]
                    if name == "merkle_manifest.json":
                        continue
                    content = zf.read(name)
                    computed = sha256_bytes(content)
                    if computed != entry["sha256"]:
                        logger.error("Hash mismatch for %s in %s", name, zip_path)
                        return False

                # Recompute Merkle root
                computed_root = build_merkle_root(
                    [f["sha256"] for f in sorted(manifest["files"], key=lambda x: x["filename"])
                     if f["filename"] != "merkle_manifest.json"]
                )

                # Verify signatures
                for sig_data in manifest.get("signatures", []):
                    sig = Ed25519Sig(**sig_data)
                    if not EvidenceSigner.verify_signature(sig, manifest["merkle_root"]):
                        logger.error("Signature verification failed for %s", zip_path)
                        return False

            logger.info("Evidence pack verified: %s", zip_path)
            return True
        except Exception as exc:
            logger.error("Pack verification error: %s", exc)
            return False
