"""
Execution Result schema for PentestAgent.

Defines the result of executing a step in an execution plan.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import Field, validator

from .base import BaseSchema


class ExecutionStatus(str, Enum):
    """Status of an execution."""
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    ABORTED = "aborted"
    PENDING = "pending"


class ErrorClass(str, Enum):
    """Classification of errors."""
    NETWORK = "network"          # Network connectivity issues
    AUTH = "auth"                # Authentication/authorization failures
    SCOPE = "scope"              # Scope violation
    PARSE = "parse"              # Output parsing errors
    TIMEOUT = "timeout"          # Operation timed out
    PERMISSION = "permission"    # Permission denied
    NOT_FOUND = "not_found"      # Target/resource not found
    PRECONDITION = "precondition"  # Precondition not met
    TOOL_ERROR = "tool_error"    # Tool-specific error
    UNKNOWN = "unknown"          # Unknown error


class ExecutionResult(BaseSchema):
    """
    Result of executing a step in an execution plan.

    Records what happened when a step was executed, including
    success/failure status, evidence, and any errors.
    """

    plan_id: str = Field(
        ...,
        description="ID of the ExecutionPlan this result belongs to",
    )
    step_index: int = Field(
        ...,
        ge=0,
        description="Index of the step that was executed",
    )
    status: ExecutionStatus = Field(
        default=ExecutionStatus.PENDING,
        description="Execution status",
    )
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs (logs, outputs, screenshots, etc.)",
    )
    started_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When execution started",
    )
    completed_at: Optional[datetime] = Field(
        None,
        description="When execution completed",
    )
    duration_ms: Optional[int] = Field(
        None,
        ge=0,
        description="Execution duration in milliseconds",
    )
    output_summary: Optional[str] = Field(
        None,
        description="Summary of the execution output",
    )
    raw_output_preview: Optional[str] = Field(
        None,
        description="Preview of raw output (truncated)",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )
    error_class: Optional[ErrorClass] = Field(
        None,
        description="Classification of error if failed",
    )
    error_message: Optional[str] = Field(
        None,
        description="Error message if failed",
    )
    error_details: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional error details",
    )
    command_executed: Optional[str] = Field(
        None,
        description="Actual command/action that was executed",
    )
    parameters_used: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters that were used",
    )
    exit_code: Optional[int] = Field(
        None,
        description="Exit code of the tool/command",
    )
    success_criteria_met: List[str] = Field(
        default_factory=list,
        description="Success criteria that were met",
    )
    success_criteria_failed: List[str] = Field(
        default_factory=list,
        description="Success criteria that failed",
    )
    requires_followup: bool = Field(
        default=False,
        description="Whether this result requires follow-up action",
    )
    followup_action: Optional[str] = Field(
        None,
        description="Recommended follow-up action",
    )
    rollback_executed: bool = Field(
        default=False,
        description="Whether rollback was executed",
    )
    rollback_notes: Optional[str] = Field(
        None,
        description="Notes about rollback execution",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes",
    )

    @validator("plan_id")
    def validate_plan_id(cls, v: str) -> str:
        """Validate plan_id is not empty."""
        if not v or not v.strip():
            raise ValueError("plan_id cannot be empty")
        return v.strip()

    def mark_success(
        self,
        output_summary: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
    ) -> None:
        """Mark execution as successful."""
        self.status = ExecutionStatus.SUCCESS
        self.completed_at = datetime.utcnow()
        self._calculate_duration()

        if output_summary:
            self.output_summary = output_summary
        if evidence_ids:
            self.evidence_ids.extend(evidence_ids)

    def mark_failure(
        self,
        error_class: ErrorClass,
        error_message: str,
        error_details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Mark execution as failed."""
        self.status = ExecutionStatus.FAILURE
        self.completed_at = datetime.utcnow()
        self._calculate_duration()

        self.error_class = error_class
        self.error_message = error_message
        if error_details:
            self.error_details = error_details

    def mark_timeout(self) -> None:
        """Mark execution as timed out."""
        self.status = ExecutionStatus.TIMEOUT
        self.completed_at = datetime.utcnow()
        self._calculate_duration()
        self.error_class = ErrorClass.TIMEOUT
        self.error_message = "Execution timed out"

    def mark_skipped(self, reason: str) -> None:
        """Mark execution as skipped."""
        self.status = ExecutionStatus.SKIPPED
        self.completed_at = datetime.utcnow()
        self.output_summary = f"Skipped: {reason}"

    def _calculate_duration(self) -> None:
        """Calculate execution duration."""
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            self.duration_ms = int(delta.total_seconds() * 1000)

    def add_evidence(self, evidence_id: str) -> None:
        """Add an evidence ID."""
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    def is_successful(self) -> bool:
        """Check if execution was successful."""
        return self.status == ExecutionStatus.SUCCESS

    def is_retriable(self) -> bool:
        """Check if the execution can be retried."""
        retriable_classes = {
            ErrorClass.NETWORK,
            ErrorClass.TIMEOUT,
        }
        return (
            self.status == ExecutionStatus.FAILURE
            and self.error_class in retriable_classes
        )

    def needs_escalation(self) -> bool:
        """Check if this result needs human escalation."""
        escalation_classes = {
            ErrorClass.SCOPE,
            ErrorClass.UNKNOWN,
        }
        return (
            self.status == ExecutionStatus.FAILURE
            and self.error_class in escalation_classes
        )
