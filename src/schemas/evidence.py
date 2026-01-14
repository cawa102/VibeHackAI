"""
Evidence Item schema for PentestAgent.

Defines the metadata for evidence stored in the Evidence Ledger.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Dict, Any, List

from pydantic import BaseModel, Field, validator


class EvidenceItem(BaseModel):
    """
    Metadata reference to evidence stored in the Evidence Ledger.

    This schema represents the metadata about evidence, not the evidence itself.
    The actual evidence data is stored in the Evidence Ledger and referenced
    by evidence_id.
    """

    evidence_id: str = Field(
        ...,
        description="Reference to evidence in Evidence Ledger (ev-<uuid>)",
    )
    file_path: str = Field(
        ...,
        description="Path to the raw evidence file",
    )
    sha256: str = Field(
        ...,
        description="SHA256 hash of the evidence data",
    )
    size_bytes: int = Field(
        ...,
        ge=0,
        description="Size of evidence in bytes",
    )
    mime_type: Optional[str] = Field(
        None,
        description="MIME type of the evidence",
    )
    extension: str = Field(
        default="bin",
        description="File extension",
    )
    source_tool: str = Field(
        ...,
        description="Tool that generated this evidence",
    )
    query_params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters used to generate this evidence",
    )
    response_code: Optional[int] = Field(
        None,
        description="HTTP response code or tool exit code",
    )
    stored_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the evidence was stored",
    )
    description: Optional[str] = Field(
        None,
        description="Human-readable description of the evidence",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization",
    )

    class Config:
        extra = "allow"  # Allow additional metadata

    @validator("evidence_id")
    def validate_evidence_id(cls, v: str) -> str:
        """Validate evidence_id format."""
        if not v or not v.strip():
            raise ValueError("evidence_id cannot be empty")
        if not v.startswith("ev-"):
            raise ValueError("evidence_id must start with 'ev-'")
        return v.strip()

    @validator("sha256")
    def validate_sha256(cls, v: str) -> str:
        """Validate SHA256 hash format."""
        if not v or len(v) != 64:
            raise ValueError("sha256 must be a 64-character hex string")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("sha256 must be a valid hex string")
        return v.lower()

    @classmethod
    def from_ledger_meta(cls, meta: dict) -> "EvidenceItem":
        """
        Create EvidenceItem from Evidence Ledger metadata.

        Args:
            meta: Metadata dictionary from EvidenceLedger.store()

        Returns:
            EvidenceItem instance.
        """
        return cls(
            evidence_id=meta["evidence_id"],
            file_path=meta["file_path"],
            sha256=meta["sha256"],
            size_bytes=meta["size_bytes"],
            mime_type=meta.get("mime_type"),
            extension=meta.get("extension", "bin"),
            source_tool=meta["source_tool"],
            query_params=meta.get("query_params", {}),
            response_code=meta.get("response_code"),
            stored_at=datetime.fromisoformat(meta["stored_at"].rstrip("Z")),
        )
