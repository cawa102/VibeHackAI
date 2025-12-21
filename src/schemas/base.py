"""
Base schema definitions for PentestAgent.

Provides the base class with common fields for all schema objects.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, validator


# Current schema version
SCHEMA_VERSION = "1.0.0"


class SchemaVersion:
    """Schema version constants."""
    CURRENT = SCHEMA_VERSION
    V1_0_0 = "1.0.0"


class BaseSchema(BaseModel):
    """
    Base schema with common fields for all objects.

    All schema objects inherit from this class and share these fields:
    - id: Unique identifier (UUID v4)
    - session_id: Session this object belongs to
    - created_at: Creation timestamp (ISO 8601)
    - created_by: Creator identifier (agent name, "orchestrator", or "human")
    - scope_tag: Scope identifier for the target
    - schema_version: Version of the schema (semver)
    """

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier (UUID v4)",
    )
    session_id: str = Field(
        ...,
        description="Session ID this object belongs to",
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Creation timestamp (UTC)",
    )
    created_by: str = Field(
        ...,
        description="Creator identifier (agent name, 'orchestrator', or 'human')",
    )
    scope_tag: str = Field(
        ...,
        description="Scope tag identifying the target",
    )
    schema_version: str = Field(
        default=SCHEMA_VERSION,
        description="Schema version (semver)",
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z" if v else None,
        }
        extra = "forbid"

    @validator("id", pre=True, always=True)
    def ensure_id(cls, v: Optional[str]) -> str:
        """Generate ID if not provided."""
        if v is None or v == "":
            return str(uuid.uuid4())
        return v

    @validator("created_by")
    def validate_created_by(cls, v: str) -> str:
        """Validate created_by is not empty."""
        if not v or not v.strip():
            raise ValueError("created_by cannot be empty")
        return v.strip()

    @validator("scope_tag")
    def validate_scope_tag(cls, v: str) -> str:
        """Validate scope_tag is not empty."""
        if not v or not v.strip():
            raise ValueError("scope_tag cannot be empty")
        return v.strip()

    def to_dict(self) -> dict:
        """Convert to dictionary with ISO formatted datetime."""
        data = self.dict()
        if isinstance(data.get("created_at"), datetime):
            data["created_at"] = data["created_at"].isoformat() + "Z"
        return data

    @classmethod
    def generate_id(cls) -> str:
        """Generate a new UUID v4 ID."""
        return str(uuid.uuid4())
