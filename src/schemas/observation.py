"""
Observation schema for PentestAgent.

Defines the record of MCP tool executions and their results.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import Field, validator

from .base import BaseSchema


class ObservationStatus(str, Enum):
    """Status of an observation/tool execution."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class Observation(BaseSchema):
    """
    Record of a tool execution and its observations.

    Every MCP call should generate an Observation to maintain
    audit trail and observability.
    """

    tool: str = Field(
        ...,
        description="Name of the tool/MCP server used",
    )
    action: str = Field(
        ...,
        description="Specific action performed",
    )
    target: Optional[str] = Field(
        None,
        description="Target of the action (IP, URL, etc.)",
    )
    status: ObservationStatus = Field(
        default=ObservationStatus.SUCCESS,
        description="Status of the execution",
    )
    success: bool = Field(
        default=True,
        description="Whether the execution was successful",
    )
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs for the raw output",
    )
    summary: Optional[str] = Field(
        None,
        description="Human-readable summary of findings",
    )
    raw_output_preview: Optional[str] = Field(
        None,
        description="Preview of raw output (truncated)",
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters used for the tool call",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )
    exit_code: Optional[int] = Field(
        None,
        description="Exit code of the tool",
    )
    started_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the execution started",
    )
    completed_at: Optional[datetime] = Field(
        None,
        description="When the execution completed",
    )
    duration_ms: Optional[int] = Field(
        None,
        ge=0,
        description="Execution duration in milliseconds",
    )
    error_message: Optional[str] = Field(
        None,
        description="Error message if execution failed",
    )
    findings_count: int = Field(
        default=0,
        ge=0,
        description="Number of findings from this observation",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization",
    )

    @validator("tool")
    def validate_tool(cls, v: str) -> str:
        """Validate tool name is not empty."""
        if not v or not v.strip():
            raise ValueError("tool cannot be empty")
        return v.strip()

    @validator("action")
    def validate_action(cls, v: str) -> str:
        """Validate action is not empty."""
        if not v or not v.strip():
            raise ValueError("action cannot be empty")
        return v.strip()

    def mark_completed(
        self,
        status: ObservationStatus = ObservationStatus.SUCCESS,
        error_message: Optional[str] = None,
    ) -> None:
        """Mark the observation as completed."""
        self.completed_at = datetime.utcnow()
        self.status = status
        self.error_message = error_message

        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            self.duration_ms = int(delta.total_seconds() * 1000)

    def add_evidence(self, evidence_id: str) -> None:
        """Add an evidence ID to this observation."""
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    @classmethod
    def create_for_tool(
        cls,
        session_id: str,
        tool: str,
        action: str,
        target: str,
        created_by: str,
        scope_tag: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> "Observation":
        """
        Factory method to create an observation for a tool execution.

        Args:
            session_id: Session ID.
            tool: Tool name.
            action: Action being performed.
            target: Target of the action.
            created_by: Agent or component creating this.
            scope_tag: Scope tag for the target.
            parameters: Tool parameters.

        Returns:
            New Observation instance.
        """
        return cls(
            session_id=session_id,
            tool=tool,
            action=action,
            target=target,
            created_by=created_by,
            scope_tag=scope_tag,
            parameters=parameters or {},
            started_at=datetime.utcnow(),
        )
