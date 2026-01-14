"""
Patch and PatchOperation classes for PentestAgent.

Defines the structure of state update proposals.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, validator

from .operations import OperationType


class PatchOperation(BaseModel):
    """
    A single operation within a patch.

    Represents one atomic state modification.
    """

    op: OperationType = Field(
        ...,
        description="Operation type",
    )
    target: str = Field(
        ...,
        description="Target identifier (schema name, object ID, etc.)",
    )
    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Operation data/parameters",
    )
    requires_approval: bool = Field(
        default=False,
        description="Whether this operation requires human approval",
    )

    @validator("target")
    def validate_target(cls, v: str) -> str:
        """Validate target is not empty."""
        if not v or not v.strip():
            raise ValueError("target cannot be empty")
        return v.strip()

    class Config:
        """Pydantic config."""
        use_enum_values = True


class Patch(BaseModel):
    """
    A state update proposal from an Agent to the Orchestrator.

    Contains one or more operations to be applied atomically.
    Uses optimistic locking via base_state_version.
    """

    patch_id: str = Field(
        default_factory=lambda: f"patch-{uuid.uuid4()}",
        description="Unique patch identifier",
    )
    session_id: str = Field(
        ...,
        description="Session this patch belongs to",
    )
    agent_id: str = Field(
        ...,
        description="Agent that created this patch",
    )
    base_state_version: int = Field(
        ...,
        ge=0,
        description="State version this patch is based on (for optimistic locking)",
    )
    operations: List[PatchOperation] = Field(
        default_factory=list,
        description="List of operations to apply",
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When this patch was created",
    )
    description: Optional[str] = Field(
        None,
        description="Human-readable description of the patch",
    )
    scope_tag: Optional[str] = Field(
        None,
        description="Scope tag for validation",
    )

    @validator("session_id")
    def validate_session_id(cls, v: str) -> str:
        """Validate session_id is not empty."""
        if not v or not v.strip():
            raise ValueError("session_id cannot be empty")
        return v.strip()

    @validator("agent_id")
    def validate_agent_id(cls, v: str) -> str:
        """Validate agent_id is not empty."""
        if not v or not v.strip():
            raise ValueError("agent_id cannot be empty")
        return v.strip()

    def add_operation(
        self,
        op: OperationType,
        target: str,
        payload: Optional[Dict[str, Any]] = None,
        requires_approval: bool = False,
    ) -> None:
        """
        Add an operation to the patch.

        Args:
            op: Operation type.
            target: Target identifier.
            payload: Operation data.
            requires_approval: Whether approval is required.
        """
        operation = PatchOperation(
            op=op,
            target=target,
            payload=payload or {},
            requires_approval=requires_approval,
        )
        self.operations.append(operation)

    def requires_approval(self) -> bool:
        """Check if any operation in this patch requires approval."""
        return any(op.requires_approval for op in self.operations)

    def get_affected_targets(self) -> List[str]:
        """Get list of all targets affected by this patch."""
        return list(set(op.target for op in self.operations))

    def operation_count(self) -> int:
        """Get the number of operations in this patch."""
        return len(self.operations)

    def is_empty(self) -> bool:
        """Check if the patch has no operations."""
        return len(self.operations) == 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert patch to dictionary for serialization."""
        return {
            "patch_id": self.patch_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "base_state_version": self.base_state_version,
            "operations": [
                {
                    "op": op.op if isinstance(op.op, str) else op.op.value,
                    "target": op.target,
                    "payload": op.payload,
                    "requires_approval": op.requires_approval,
                }
                for op in self.operations
            ],
            "created_at": self.created_at.isoformat() + "Z",
            "description": self.description,
            "scope_tag": self.scope_tag,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Patch":
        """Create a Patch from a dictionary."""
        operations = [
            PatchOperation(
                op=OperationType(op_data["op"]),
                target=op_data["target"],
                payload=op_data.get("payload", {}),
                requires_approval=op_data.get("requires_approval", False),
            )
            for op_data in data.get("operations", [])
        ]

        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.rstrip("Z"))

        return cls(
            patch_id=data.get("patch_id", f"patch-{uuid.uuid4()}"),
            session_id=data["session_id"],
            agent_id=data["agent_id"],
            base_state_version=data["base_state_version"],
            operations=operations,
            created_at=created_at or datetime.utcnow(),
            description=data.get("description"),
            scope_tag=data.get("scope_tag"),
        )

    class Config:
        """Pydantic config."""
        json_encoders = {
            datetime: lambda v: v.isoformat() + "Z",
        }
