"""
CVSS (Common Vulnerability Scoring System) schema for PentestAgent.

Defines structured CVSS scoring with version, vector, and score.
Supports CVSS 3.0, 3.1, and 4.0.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, validator


class CVSSVersion(str, Enum):
    """Supported CVSS versions."""
    V3_0 = "3.0"
    V3_1 = "3.1"
    V4_0 = "4.0"


class CVSSSeverity(str, Enum):
    """CVSS severity levels based on base score ranges."""
    NONE = "none"          # 0.0
    LOW = "low"            # 0.1 - 3.9
    MEDIUM = "medium"      # 4.0 - 6.9
    HIGH = "high"          # 7.0 - 8.9
    CRITICAL = "critical"  # 9.0 - 10.0


class CVSS(BaseModel):
    """
    CVSS (Common Vulnerability Scoring System) object.

    Provides structured scoring with version, vector string, and numeric score.
    Automatically calculates severity from base score.
    """

    version: CVSSVersion = Field(
        default=CVSSVersion.V3_1,
        description="CVSS version (3.0, 3.1, or 4.0)",
    )
    vector: Optional[str] = Field(
        None,
        description="CVSS vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    )
    base_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="CVSS base score (0.0 - 10.0)",
    )
    temporal_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=10.0,
        description="CVSS temporal score (0.0 - 10.0)",
    )
    environmental_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=10.0,
        description="CVSS environmental score (0.0 - 10.0)",
    )
    severity: Optional[CVSSSeverity] = Field(
        None,
        description="Severity level (auto-calculated from base_score if not provided)",
    )

    @validator("vector")
    def validate_vector(cls, v: Optional[str], values) -> Optional[str]:
        """Validate CVSS vector format."""
        if v is None:
            return None

        v = v.strip().upper()

        # Validate version prefix
        version = values.get("version", CVSSVersion.V3_1)
        expected_prefix = f"CVSS:{version.value}/"

        if not v.startswith("CVSS:"):
            # Add prefix if missing
            v = expected_prefix + v
        elif not v.startswith(expected_prefix):
            # Validate version matches
            if v.startswith("CVSS:3.0/") and version != CVSSVersion.V3_0:
                pass  # Allow mismatch, vector takes precedence
            elif v.startswith("CVSS:3.1/") and version != CVSSVersion.V3_1:
                pass
            elif v.startswith("CVSS:4.0/") and version != CVSSVersion.V4_0:
                pass

        return v

    @validator("severity", always=True, pre=True)
    def calculate_severity(cls, v, values) -> CVSSSeverity:
        """Calculate severity from base score if not provided."""
        if v is not None:
            return v

        base_score = values.get("base_score", 0.0)
        return cls._score_to_severity(base_score)

    @staticmethod
    def _score_to_severity(score: float) -> CVSSSeverity:
        """Convert CVSS score to severity level."""
        if score == 0.0:
            return CVSSSeverity.NONE
        elif score < 4.0:
            return CVSSSeverity.LOW
        elif score < 7.0:
            return CVSSSeverity.MEDIUM
        elif score < 9.0:
            return CVSSSeverity.HIGH
        else:
            return CVSSSeverity.CRITICAL

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "version": self.version.value,
            "vector": self.vector,
            "base_score": self.base_score,
            "temporal_score": self.temporal_score,
            "environmental_score": self.environmental_score,
            "severity": self.severity.value if self.severity else None,
        }

    def to_display_string(self) -> str:
        """Format for display in reports."""
        severity_str = self.severity.value.upper() if self.severity else "UNKNOWN"
        return f"CVSS {self.version.value}: {self.base_score} ({severity_str})"

    @classmethod
    def from_score(
        cls,
        score: float,
        version: CVSSVersion = CVSSVersion.V3_1,
        vector: Optional[str] = None,
    ) -> "CVSS":
        """Create CVSS from score only."""
        return cls(
            version=version,
            vector=vector,
            base_score=score,
        )

    @classmethod
    def unknown(cls) -> "CVSS":
        """Create unknown/unassessed CVSS."""
        return cls(
            version=CVSSVersion.V3_1,
            vector=None,
            base_score=0.0,
            severity=CVSSSeverity.NONE,
        )

    @classmethod
    def pending(cls, estimated_severity: CVSSSeverity = CVSSSeverity.MEDIUM) -> "CVSS":
        """Create pending CVSS assessment placeholder."""
        score_map = {
            CVSSSeverity.NONE: 0.0,
            CVSSSeverity.LOW: 2.0,
            CVSSSeverity.MEDIUM: 5.0,
            CVSSSeverity.HIGH: 7.5,
            CVSSSeverity.CRITICAL: 9.5,
        }
        return cls(
            version=CVSSVersion.V3_1,
            vector=None,
            base_score=score_map.get(estimated_severity, 5.0),
            severity=estimated_severity,
        )

    def is_high_or_critical(self) -> bool:
        """Check if severity is high or critical."""
        return self.severity in (CVSSSeverity.HIGH, CVSSSeverity.CRITICAL)

    def is_assessed(self) -> bool:
        """Check if CVSS has been properly assessed (has vector)."""
        return self.vector is not None


class CVSSAssessmentStatus(str, Enum):
    """Status of CVSS assessment."""
    CONFIRMED = "confirmed"      # Verified from official source
    ESTIMATED = "estimated"      # Estimated based on vulnerability type
    PENDING = "pending"          # Awaiting assessment
    NOT_APPLICABLE = "n/a"       # CVSS not applicable


class CVSSWithStatus(BaseModel):
    """
    CVSS with assessment status for reporting.

    Indicates whether the CVSS is confirmed, estimated, or pending.
    """

    cvss: CVSS = Field(..., description="CVSS scoring object")
    status: CVSSAssessmentStatus = Field(
        default=CVSSAssessmentStatus.PENDING,
        description="Assessment status",
    )
    source: Optional[str] = Field(
        None,
        description="Source of CVSS data (NVD, vendor, manual, etc.)",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes about the assessment",
    )

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "cvss": self.cvss.to_dict(),
            "status": self.status.value,
            "source": self.source,
            "notes": self.notes,
        }

    def to_report_string(self) -> str:
        """Format for report output."""
        status_indicator = {
            CVSSAssessmentStatus.CONFIRMED: "",
            CVSSAssessmentStatus.ESTIMATED: " (estimated)",
            CVSSAssessmentStatus.PENDING: " (pending confirmation)",
            CVSSAssessmentStatus.NOT_APPLICABLE: " (N/A)",
        }
        return self.cvss.to_display_string() + status_indicator.get(self.status, "")
