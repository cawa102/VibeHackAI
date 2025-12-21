"""
Evidence Ledger for PentestAgent.

Provides append-only storage for evidence with SHA256 integrity verification.
Evidence cannot be modified or deleted once stored.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, BinaryIO, Union


class EvidenceIntegrityError(Exception):
    """Raised when evidence integrity check fails."""
    pass


class EvidenceNotFoundError(Exception):
    """Raised when requested evidence is not found."""
    pass


class EvidenceDeletionError(Exception):
    """Raised when attempting to delete evidence."""
    pass


class EvidenceLedger:
    """
    Append-only evidence storage with SHA256 integrity verification.

    Each evidence item is stored in its own directory:
    - <evidence_id>/raw.<ext>: The raw evidence data
    - <evidence_id>/meta.json: Metadata including SHA256 hash

    Evidence cannot be modified or deleted (append-only).
    """

    def __init__(self, evidence_dir: Union[str, Path]):
        """
        Initialize EvidenceLedger.

        Args:
            evidence_dir: Directory to store evidence files.
        """
        self.evidence_dir = Path(evidence_dir).resolve()
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def _compute_sha256(self, data: bytes) -> str:
        """Compute SHA256 hash of data."""
        return hashlib.sha256(data).hexdigest()

    def _generate_evidence_id(self) -> str:
        """Generate a unique evidence ID."""
        return f"ev-{uuid.uuid4()}"

    def store(
        self,
        data: Union[bytes, str, BinaryIO],
        source_tool: str,
        extension: str = "bin",
        query_params: Optional[dict] = None,
        response_code: Optional[int] = None,
        mime_type: Optional[str] = None,
        additional_meta: Optional[dict] = None,
    ) -> dict:
        """
        Store evidence with metadata and SHA256 hash.

        Args:
            data: Evidence data (bytes, string, or file-like object).
            source_tool: Name of the tool that generated this evidence.
            extension: File extension for the raw data (without dot).
            query_params: Optional query parameters used to generate this evidence.
            response_code: Optional HTTP response code or tool exit code.
            mime_type: Optional MIME type of the data.
            additional_meta: Optional additional metadata to store.

        Returns:
            Dictionary containing evidence metadata including:
            - evidence_id: Unique identifier
            - sha256: Hash of the data
            - file_path: Path to raw data file
            - stored_at: Timestamp of storage
        """
        # Convert data to bytes
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        elif hasattr(data, "read"):
            data_bytes = data.read()
        else:
            data_bytes = data

        # Generate ID and compute hash
        evidence_id = self._generate_evidence_id()
        sha256_hash = self._compute_sha256(data_bytes)

        # Create evidence directory
        evidence_path = self.evidence_dir / evidence_id
        evidence_path.mkdir(parents=True, exist_ok=True)

        # Store raw data
        raw_filename = f"raw.{extension}"
        raw_path = evidence_path / raw_filename
        raw_path.write_bytes(data_bytes)

        # Prepare metadata
        stored_at = datetime.utcnow().isoformat() + "Z"
        meta = {
            "evidence_id": evidence_id,
            "sha256": sha256_hash,
            "size_bytes": len(data_bytes),
            "extension": extension,
            "mime_type": mime_type,
            "source_tool": source_tool,
            "query_params": query_params or {},
            "response_code": response_code,
            "stored_at": stored_at,
            "file_path": str(raw_path),
        }

        # Merge additional metadata
        if additional_meta:
            meta["additional"] = additional_meta

        # Store metadata
        meta_path = evidence_path / "meta.json"
        meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False))

        return meta

    def get(self, evidence_id: str, verify_integrity: bool = True) -> dict:
        """
        Retrieve evidence metadata.

        Args:
            evidence_id: The evidence ID to retrieve.
            verify_integrity: If True, verify SHA256 hash matches stored data.

        Returns:
            Evidence metadata dictionary.

        Raises:
            EvidenceNotFoundError: If evidence does not exist.
            EvidenceIntegrityError: If integrity check fails.
        """
        evidence_path = self.evidence_dir / evidence_id
        meta_path = evidence_path / "meta.json"

        if not meta_path.exists():
            raise EvidenceNotFoundError(f"Evidence not found: {evidence_id}")

        meta = json.loads(meta_path.read_text())

        if verify_integrity:
            raw_path = Path(meta["file_path"])
            if not raw_path.exists():
                raise EvidenceIntegrityError(
                    f"Raw data file missing for evidence: {evidence_id}"
                )

            actual_hash = self._compute_sha256(raw_path.read_bytes())
            if actual_hash != meta["sha256"]:
                raise EvidenceIntegrityError(
                    f"SHA256 mismatch for evidence {evidence_id}: "
                    f"expected {meta['sha256']}, got {actual_hash}"
                )

        return meta

    def get_raw_data(self, evidence_id: str, verify_integrity: bool = True) -> bytes:
        """
        Retrieve raw evidence data.

        Args:
            evidence_id: The evidence ID to retrieve.
            verify_integrity: If True, verify SHA256 hash matches stored data.

        Returns:
            Raw evidence data as bytes.

        Raises:
            EvidenceNotFoundError: If evidence does not exist.
            EvidenceIntegrityError: If integrity check fails.
        """
        meta = self.get(evidence_id, verify_integrity=verify_integrity)
        raw_path = Path(meta["file_path"])
        return raw_path.read_bytes()

    def list_evidence(self) -> list[dict]:
        """
        List all evidence items.

        Returns:
            List of evidence metadata dictionaries.
        """
        evidence_list = []

        for evidence_dir in self.evidence_dir.iterdir():
            if evidence_dir.is_dir():
                meta_path = evidence_dir / "meta.json"
                if meta_path.exists():
                    try:
                        meta = json.loads(meta_path.read_text())
                        evidence_list.append(meta)
                    except json.JSONDecodeError:
                        continue

        # Sort by storage time, newest first
        evidence_list.sort(key=lambda x: x.get("stored_at", ""), reverse=True)
        return evidence_list

    def exists(self, evidence_id: str) -> bool:
        """Check if evidence exists."""
        meta_path = self.evidence_dir / evidence_id / "meta.json"
        return meta_path.exists()

    def delete(self, evidence_id: str) -> None:
        """
        Attempt to delete evidence (ALWAYS FAILS).

        Evidence deletion is prohibited to maintain referential integrity
        and audit trail.

        Raises:
            EvidenceDeletionError: Always raised.
        """
        raise EvidenceDeletionError(
            f"Evidence deletion is prohibited: {evidence_id}. "
            "Evidence is append-only to maintain integrity and audit trail."
        )

    def verify_all(self) -> list[dict]:
        """
        Verify integrity of all evidence.

        Returns:
            List of dictionaries containing verification results:
            - evidence_id: The evidence ID
            - valid: True if integrity check passed
            - error: Error message if check failed
        """
        results = []

        for evidence_dir in self.evidence_dir.iterdir():
            if evidence_dir.is_dir():
                evidence_id = evidence_dir.name
                result = {"evidence_id": evidence_id, "valid": False, "error": None}

                try:
                    self.get(evidence_id, verify_integrity=True)
                    result["valid"] = True
                except (EvidenceNotFoundError, EvidenceIntegrityError) as e:
                    result["error"] = str(e)

                results.append(result)

        return results
