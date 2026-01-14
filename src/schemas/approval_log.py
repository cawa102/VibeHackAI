"""
ApprovalLog and OverrideLog schemas for PentestAgent.

Provides audit trail for all approval decisions and override actions.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ApprovalDecision(str, Enum):
    """Possible approval decisions."""
    APPROVED = "approved"
    REJECTED = "rejected"
    DEFERRED = "deferred"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ApprovalType(str, Enum):
    """Types of approval requests."""
    PHASE_START = "phase_start"
    PHASE_ESCALATION = "phase_escalation"
    OPERATION_EXECUTION = "operation_execution"
    OVERRIDE_REQUEST = "override_request"
    PLAN_UPDATE = "plan_update"


class ApprovalLog(BaseModel):
    """
    Audit log for approval decisions.

    Records who approved/rejected what, when, and why.
    Used for traceability and compliance.
    """

    log_id: str = Field(
        default_factory=lambda: f"approval-{uuid.uuid4().hex[:8]}",
        description="Unique log entry identifier",
    )
    session_id: str = Field(
        ...,
        description="Session this approval belongs to",
    )
    approval_type: ApprovalType = Field(
        ...,
        description="Type of approval",
    )
    phase: str = Field(
        ...,
        description="Phase this approval is for",
    )
    brief_id: Optional[str] = Field(
        None,
        description="Associated PhaseBrief ID",
    )
    request_summary: str = Field(
        ...,
        description="Human-readable summary of what was requested",
    )
    decision: ApprovalDecision = Field(
        ...,
        description="The approval decision made",
    )
    approved_by: str = Field(
        ...,
        description="Who made the decision (user identifier)",
    )
    approved_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="When the decision was made",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes from the approver",
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context at time of approval",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "log_id": self.log_id,
            "session_id": self.session_id,
            "approval_type": self.approval_type.value,
            "phase": self.phase,
            "brief_id": self.brief_id,
            "request_summary": self.request_summary,
            "decision": self.decision.value,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "notes": self.notes,
            "context": self.context,
        }

    def to_audit_string(self) -> str:
        """Format for audit log display."""
        return (
            f"[{self.approved_at}] {self.approval_type.value}: "
            f"{self.decision.value.upper()} by {self.approved_by} - "
            f"{self.request_summary}"
        )


class OverrideCategory(str, Enum):
    """Categories of operations that can be overridden."""
    SAFETY_POLICY = "safety_policy"
    SCOPE_BOUNDARY = "scope_boundary"
    RATE_LIMIT = "rate_limit"
    EXPLOITATION_LIMIT = "exploitation_limit"
    DATA_ACCESS_LIMIT = "data_access_limit"
    TOOL_RESTRICTION = "tool_restriction"
    # NOT_ALLOWED categories - cannot be overridden
    # DESTRUCTIVE = "destructive"  # Never allow
    # OUT_OF_SCOPE = "out_of_scope"  # Never allow


class OverrideStatus(str, Enum):
    """Status of override request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class OverrideLog(BaseModel):
    """
    Audit log for override actions.

    Records when a human explicitly overrides a safety/policy stop.
    These are HIGH VISIBILITY audit entries for compliance.
    """

    override_id: str = Field(
        default_factory=lambda: f"override-{uuid.uuid4().hex[:8]}",
        description="Unique override identifier",
    )
    session_id: str = Field(
        ...,
        description="Session this override belongs to",
    )
    category: OverrideCategory = Field(
        ...,
        description="Category of override",
    )
    original_stop_reason: str = Field(
        ...,
        description="Original reason why operation was stopped",
    )
    override_reason: str = Field(
        ...,
        description="Reason provided for override",
    )
    approved_by: str = Field(
        ...,
        description="Who approved the override",
    )
    approved_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="When override was approved",
    )
    status: OverrideStatus = Field(
        default=OverrideStatus.APPROVED,
        description="Status of the override",
    )
    linked_phase: str = Field(
        ...,
        description="Phase where override occurred",
    )
    linked_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs linked to overridden operations",
    )
    linked_brief_id: Optional[str] = Field(
        None,
        description="Associated PhaseBrief ID",
    )
    risk_acknowledgment: str = Field(
        default="User has acknowledged the risks of this override.",
        description="Risk acknowledgment statement",
    )
    expiry: Optional[str] = Field(
        None,
        description="When this override expires (if applicable)",
    )
    scope_of_override: Dict[str, Any] = Field(
        default_factory=dict,
        description="Specific scope/limits of what is overridden",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "override_id": self.override_id,
            "session_id": self.session_id,
            "category": self.category.value,
            "original_stop_reason": self.original_stop_reason,
            "override_reason": self.override_reason,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "status": self.status.value,
            "linked_phase": self.linked_phase,
            "linked_evidence_ids": self.linked_evidence_ids,
            "linked_brief_id": self.linked_brief_id,
            "risk_acknowledgment": self.risk_acknowledgment,
            "expiry": self.expiry,
            "scope_of_override": self.scope_of_override,
        }

    def to_audit_string(self) -> str:
        """Format for audit log display."""
        return (
            f"[{self.approved_at}] OVERRIDE ({self.category.value}): "
            f"Approved by {self.approved_by} - "
            f"Original stop: {self.original_stop_reason} -> "
            f"Override reason: {self.override_reason}"
        )

    def is_valid(self) -> bool:
        """Check if override is still valid."""
        if self.status != OverrideStatus.APPROVED:
            return False
        if self.expiry:
            try:
                expiry_dt = datetime.fromisoformat(self.expiry.rstrip("Z"))
                if datetime.utcnow() > expiry_dt:
                    return False
            except ValueError:
                pass
        return True


class StopReport(BaseModel):
    """
    Report when an agent stops due to safety/policy.

    Used to communicate stop events to the human for override decision.
    """

    report_id: str = Field(
        default_factory=lambda: f"stop-{uuid.uuid4().hex[:8]}",
        description="Unique report identifier",
    )
    session_id: str = Field(
        ...,
        description="Session where stop occurred",
    )
    phase: str = Field(
        ...,
        description="Phase where stop occurred",
    )
    agent: str = Field(
        ...,
        description="Agent that initiated the stop",
    )
    stop_reason: str = Field(
        ...,
        description="Why the operation was stopped",
    )
    stop_category: str = Field(
        ...,
        description="Category of stop (safety, scope, policy, error)",
    )
    can_override: bool = Field(
        default=False,
        description="Whether this stop can be overridden",
    )
    override_category: Optional[OverrideCategory] = Field(
        None,
        description="Category if override is possible",
    )
    alternatives: List[str] = Field(
        default_factory=list,
        description="Alternative approaches that don't require override",
    )
    impact_if_continue: str = Field(
        default="Unknown impact",
        description="Impact assessment if override is granted",
    )
    recommendation: str = Field(
        default="Consider alternatives before overriding",
        description="Agent's recommendation",
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context about the stop",
    )
    stopped_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="When the stop occurred",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "session_id": self.session_id,
            "phase": self.phase,
            "agent": self.agent,
            "stop_reason": self.stop_reason,
            "stop_category": self.stop_category,
            "can_override": self.can_override,
            "override_category": self.override_category.value if self.override_category else None,
            "alternatives": self.alternatives,
            "impact_if_continue": self.impact_if_continue,
            "recommendation": self.recommendation,
            "context": self.context,
            "stopped_at": self.stopped_at,
        }

    def to_human_display(self) -> str:
        """Format for human display."""
        lines = [
            "## Operation Stopped",
            "",
            f"**Reason:** {self.stop_reason}",
            f"**Category:** {self.stop_category}",
            f"**Agent:** {self.agent}",
            f"**Phase:** {self.phase}",
            "",
        ]

        if self.can_override:
            lines.extend([
                "### Override Available",
                f"This stop can be overridden (category: {self.override_category.value if self.override_category else 'N/A'})",
                "",
                f"**Impact if continued:** {self.impact_if_continue}",
                "",
            ])
        else:
            lines.extend([
                "### Override NOT Available",
                "This stop cannot be overridden for safety reasons.",
                "",
            ])

        if self.alternatives:
            lines.extend([
                "### Alternatives",
            ])
            for alt in self.alternatives:
                lines.append(f"- {alt}")
            lines.append("")

        lines.append(f"**Recommendation:** {self.recommendation}")

        return "\n".join(lines)


# Categories that CANNOT be overridden
NON_OVERRIDABLE_CATEGORIES = {
    "destructive_operation",
    "out_of_scope_target",
    "malware_creation",
    "data_exfiltration",
    "permanent_modification",
    "service_disruption",
}


def can_override_stop(stop_category: str) -> bool:
    """Check if a stop category can be overridden."""
    return stop_category.lower() not in NON_OVERRIDABLE_CATEGORIES
