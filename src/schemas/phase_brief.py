"""
PhaseBrief schema for PentestAgent.

Defines the human-friendly phase briefing structure for approval flow.
Commands are hidden from standard output; only natural language summaries are shown.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class PhaseType(str, Enum):
    """Types of penetration test phases."""
    PLANNING = "planning"
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class RiskLevel(str, Enum):
    """Risk levels for phase operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SafetyConstraint(BaseModel):
    """
    Safety constraint for phase execution.

    Defines limits and boundaries that must be respected during phase execution.
    """

    constraint_id: str = Field(
        default_factory=lambda: f"constraint-{uuid.uuid4().hex[:8]}",
        description="Unique constraint identifier",
    )
    description: str = Field(
        ...,
        description="Human-readable description of the constraint",
    )
    constraint_type: str = Field(
        ...,
        description="Type of constraint (rate_limit, scope, data, time, etc.)",
    )
    value: Any = Field(
        ...,
        description="Constraint value or limit",
    )
    enforced: bool = Field(
        default=True,
        description="Whether constraint is actively enforced",
    )


class PlannedAction(BaseModel):
    """
    Planned action for human summary.

    Describes what will be done in natural language WITHOUT showing commands.
    """

    action_id: str = Field(
        default_factory=lambda: f"action-{uuid.uuid4().hex[:8]}",
        description="Unique action identifier",
    )
    summary: str = Field(
        ...,
        description="Natural language summary of the action (NO commands)",
    )
    objective: str = Field(
        ...,
        description="What this action aims to achieve",
    )
    target_description: str = Field(
        ...,
        description="Description of what will be targeted (e.g., 'web server on port 80')",
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.MEDIUM,
        description="Risk level of this specific action",
    )
    requires_approval: bool = Field(
        default=False,
        description="Whether this specific action requires additional approval",
    )
    estimated_duration: Optional[str] = Field(
        None,
        description="Estimated duration (e.g., '2-5 minutes')",
    )

    # Internal fields (not shown to user in standard mode)
    _internal_tool: Optional[str] = None
    _internal_command_hash: Optional[str] = None


class PhaseBrief(BaseModel):
    """
    Phase Brief for human approval.

    Contains all information needed for a human to understand and approve
    the next phase of penetration testing. Commands are NOT included -
    only natural language summaries.
    """

    brief_id: str = Field(
        default_factory=lambda: f"brief-{uuid.uuid4().hex[:8]}",
        description="Unique brief identifier",
    )
    phase: PhaseType = Field(
        ...,
        description="Phase type being briefed",
    )
    title: str = Field(
        ...,
        description="Brief title for display",
    )
    objective: str = Field(
        ...,
        description="Main objective of this phase in natural language",
    )
    rationale: str = Field(
        ...,
        description="Why this phase is being proposed now",
    )
    planned_actions: List[PlannedAction] = Field(
        default_factory=list,
        description="List of planned actions (natural language)",
    )
    risk_notes: List[str] = Field(
        default_factory=list,
        description="Risk considerations for the human",
    )
    safety_constraints: List[SafetyConstraint] = Field(
        default_factory=list,
        description="Safety constraints that will be enforced",
    )
    expected_outcomes: List[str] = Field(
        default_factory=list,
        description="What outcomes are expected from this phase",
    )
    fallback_options: List[str] = Field(
        default_factory=list,
        description="Alternative approaches if primary fails",
    )
    overall_risk_level: RiskLevel = Field(
        default=RiskLevel.MEDIUM,
        description="Overall risk level of the phase",
    )
    requires_phase_approval: bool = Field(
        default=True,
        description="Whether phase requires approval before starting",
    )
    evidence_policy: str = Field(
        default="All operations will be logged and evidence collected.",
        description="How evidence will be collected during this phase",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="When this brief was created",
    )
    created_by: str = Field(
        default="planner_agent",
        description="Agent that created this brief",
    )

    # Reference to detailed plan (internal, not shown to user)
    _plan_id: Optional[str] = None
    _state_version: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "brief_id": self.brief_id,
            "phase": self.phase.value,
            "title": self.title,
            "objective": self.objective,
            "rationale": self.rationale,
            "planned_actions": [
                {
                    "action_id": a.action_id,
                    "summary": a.summary,
                    "objective": a.objective,
                    "target_description": a.target_description,
                    "risk_level": a.risk_level.value,
                    "requires_approval": a.requires_approval,
                    "estimated_duration": a.estimated_duration,
                }
                for a in self.planned_actions
            ],
            "risk_notes": self.risk_notes,
            "safety_constraints": [
                {
                    "constraint_id": c.constraint_id,
                    "description": c.description,
                    "constraint_type": c.constraint_type,
                    "value": c.value,
                    "enforced": c.enforced,
                }
                for c in self.safety_constraints
            ],
            "expected_outcomes": self.expected_outcomes,
            "fallback_options": self.fallback_options,
            "overall_risk_level": self.overall_risk_level.value,
            "requires_phase_approval": self.requires_phase_approval,
            "evidence_policy": self.evidence_policy,
            "created_at": self.created_at,
            "created_by": self.created_by,
        }

    def to_human_display(self) -> str:
        """
        Format brief for human display.

        Returns natural language summary WITHOUT any commands or technical details.
        """
        lines = [
            f"## {self.title}",
            "",
            f"**Phase:** {self.phase.value.replace('_', ' ').title()}",
            f"**Risk Level:** {self.overall_risk_level.value.upper()}",
            "",
            "### Objective",
            self.objective,
            "",
            "### Rationale",
            self.rationale,
            "",
            "### Planned Actions",
        ]

        for i, action in enumerate(self.planned_actions, 1):
            risk_badge = f" [{action.risk_level.value.upper()}]" if action.risk_level != RiskLevel.LOW else ""
            approval_badge = " (requires approval)" if action.requires_approval else ""
            lines.append(f"{i}. {action.summary}{risk_badge}{approval_badge}")
            lines.append(f"   - Target: {action.target_description}")
            lines.append(f"   - Goal: {action.objective}")
            if action.estimated_duration:
                lines.append(f"   - Duration: {action.estimated_duration}")

        if self.risk_notes:
            lines.extend([
                "",
                "### Risk Considerations",
            ])
            for note in self.risk_notes:
                lines.append(f"- {note}")

        if self.safety_constraints:
            lines.extend([
                "",
                "### Safety Constraints",
            ])
            for constraint in self.safety_constraints:
                lines.append(f"- {constraint.description}")

        if self.expected_outcomes:
            lines.extend([
                "",
                "### Expected Outcomes",
            ])
            for outcome in self.expected_outcomes:
                lines.append(f"- {outcome}")

        lines.extend([
            "",
            f"**Evidence Policy:** {self.evidence_policy}",
        ])

        return "\n".join(lines)


class PhasePlan(BaseModel):
    """
    Internal phase plan with detailed execution information.

    Contains technical details (tools, commands) that are NOT shown to users.
    This is the internal counterpart to PhaseBrief.
    """

    plan_id: str = Field(
        default_factory=lambda: f"plan-{uuid.uuid4().hex[:8]}",
        description="Unique plan identifier",
    )
    brief_id: str = Field(
        ...,
        description="Associated PhaseBrief ID",
    )
    phase: PhaseType = Field(
        ...,
        description="Phase type",
    )
    steps: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Detailed execution steps (internal)",
    )
    tool_selections: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Tools to be used (internal)",
    )
    constraints: Dict[str, Any] = Field(
        default_factory=dict,
        description="Technical constraints (internal)",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "plan_id": self.plan_id,
            "brief_id": self.brief_id,
            "phase": self.phase.value,
            "steps": self.steps,
            "tool_selections": self.tool_selections,
            "constraints": self.constraints,
            "created_at": self.created_at,
        }


class PhaseResult(BaseModel):
    """
    Result summary from a completed phase.

    Used to provide feedback to Planner for next phase planning.
    """

    result_id: str = Field(
        default_factory=lambda: f"result-{uuid.uuid4().hex[:8]}",
        description="Unique result identifier",
    )
    phase: PhaseType = Field(
        ...,
        description="Phase that was executed",
    )
    brief_id: str = Field(
        ...,
        description="Associated PhaseBrief ID",
    )
    success: bool = Field(
        ...,
        description="Whether phase completed successfully",
    )
    summary: str = Field(
        ...,
        description="Natural language summary of results",
    )
    key_findings: List[str] = Field(
        default_factory=list,
        description="Key findings from this phase",
    )
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs collected during this phase",
    )
    next_phase_recommendations: List[str] = Field(
        default_factory=list,
        description="Recommendations for next phase",
    )
    issues_encountered: List[str] = Field(
        default_factory=list,
        description="Issues or problems encountered",
    )
    requires_rollback: bool = Field(
        default=False,
        description="Whether results suggest rolling back to previous phase",
    )
    rollback_reason: Optional[str] = Field(
        None,
        description="Reason for rollback recommendation",
    )
    completed_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "result_id": self.result_id,
            "phase": self.phase.value,
            "brief_id": self.brief_id,
            "success": self.success,
            "summary": self.summary,
            "key_findings": self.key_findings,
            "evidence_ids": self.evidence_ids,
            "next_phase_recommendations": self.next_phase_recommendations,
            "issues_encountered": self.issues_encountered,
            "requires_rollback": self.requires_rollback,
            "rollback_reason": self.rollback_reason,
            "completed_at": self.completed_at,
        }

    def to_human_display(self) -> str:
        """Format result for human display."""
        status = "Completed Successfully" if self.success else "Completed with Issues"
        lines = [
            f"## Phase Result: {self.phase.value.replace('_', ' ').title()}",
            "",
            f"**Status:** {status}",
            "",
            "### Summary",
            self.summary,
        ]

        if self.key_findings:
            lines.extend([
                "",
                "### Key Findings",
            ])
            for finding in self.key_findings:
                lines.append(f"- {finding}")

        if self.issues_encountered:
            lines.extend([
                "",
                "### Issues Encountered",
            ])
            for issue in self.issues_encountered:
                lines.append(f"- {issue}")

        if self.next_phase_recommendations:
            lines.extend([
                "",
                "### Recommendations for Next Phase",
            ])
            for rec in self.next_phase_recommendations:
                lines.append(f"- {rec}")

        if self.requires_rollback and self.rollback_reason:
            lines.extend([
                "",
                f"**Rollback Recommended:** {self.rollback_reason}",
            ])

        lines.extend([
            "",
            f"**Evidence Collected:** {len(self.evidence_ids)} items",
        ])

        return "\n".join(lines)
