"""
TestPlan schema for PentestAgent.

Defines the penetration test plan as a single source of truth.
The plan is created at session start and updated after each phase.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .phase_brief import PhaseType, RiskLevel


class PhaseStatus(str, Enum):
    """Status of a phase in the test plan."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    FAILED = "failed"


class PlanChangeType(str, Enum):
    """Types of changes to the test plan."""
    INITIAL_CREATION = "initial_creation"
    PHASE_COMPLETION = "phase_completion"
    PRIORITY_UPDATE = "priority_update"
    SCOPE_CHANGE = "scope_change"
    FINDING_IMPACT = "finding_impact"
    USER_MODIFICATION = "user_modification"
    ERROR_RECOVERY = "error_recovery"


class PhaseObjective(BaseModel):
    """
    Objective for a specific phase.
    """

    phase: PhaseType = Field(
        ...,
        description="Phase this objective belongs to",
    )
    objective: str = Field(
        ...,
        description="What this phase aims to achieve",
    )
    success_criteria: List[str] = Field(
        default_factory=list,
        description="Criteria for considering this phase successful",
    )
    status: PhaseStatus = Field(
        default=PhaseStatus.NOT_STARTED,
        description="Current status of this phase",
    )
    priority: int = Field(
        default=1,
        ge=1,
        le=5,
        description="Priority level (1=highest, 5=lowest)",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase.value,
            "objective": self.objective,
            "success_criteria": self.success_criteria,
            "status": self.status.value,
            "priority": self.priority,
            "notes": self.notes,
        }


class PlanChangeEntry(BaseModel):
    """
    Entry in the plan change log.

    Tracks what changed, when, why, and by whom.
    """

    change_id: str = Field(
        default_factory=lambda: f"change-{uuid.uuid4().hex[:8]}",
        description="Unique change identifier",
    )
    change_type: PlanChangeType = Field(
        ...,
        description="Type of change",
    )
    summary: str = Field(
        ...,
        description="Brief summary of what changed",
    )
    reason: str = Field(
        ...,
        description="Why this change was made",
    )
    changed_by: str = Field(
        ...,
        description="Who made the change (agent or user)",
    )
    changed_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="When the change was made",
    )
    related_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs related to this change",
    )
    related_finding_ids: List[str] = Field(
        default_factory=list,
        description="Finding IDs related to this change",
    )
    previous_values: Dict[str, Any] = Field(
        default_factory=dict,
        description="Values before the change",
    )
    new_values: Dict[str, Any] = Field(
        default_factory=dict,
        description="Values after the change",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "change_id": self.change_id,
            "change_type": self.change_type.value,
            "summary": self.summary,
            "reason": self.reason,
            "changed_by": self.changed_by,
            "changed_at": self.changed_at,
            "related_evidence_ids": self.related_evidence_ids,
            "related_finding_ids": self.related_finding_ids,
            "previous_values": self.previous_values,
            "new_values": self.new_values,
        }


class OpenQuestion(BaseModel):
    """
    Open question or uncertainty in the test plan.
    """

    question_id: str = Field(
        default_factory=lambda: f"q-{uuid.uuid4().hex[:8]}",
        description="Unique question identifier",
    )
    question: str = Field(
        ...,
        description="The question or uncertainty",
    )
    context: str = Field(
        default="",
        description="Context for this question",
    )
    priority: str = Field(
        default="medium",
        description="Priority level (high, medium, low)",
    )
    resolved: bool = Field(
        default=False,
        description="Whether this question has been resolved",
    )
    resolution: Optional[str] = Field(
        None,
        description="How the question was resolved",
    )
    resolved_at: Optional[str] = Field(
        None,
        description="When the question was resolved",
    )


class TestPlanRisk(BaseModel):
    """
    Risk identified in the test plan.
    """

    risk_id: str = Field(
        default_factory=lambda: f"risk-{uuid.uuid4().hex[:8]}",
        description="Unique risk identifier",
    )
    description: str = Field(
        ...,
        description="Description of the risk",
    )
    likelihood: str = Field(
        default="medium",
        description="Likelihood (high, medium, low)",
    )
    impact: str = Field(
        default="medium",
        description="Impact if risk materializes",
    )
    mitigation: str = Field(
        default="",
        description="Mitigation strategy",
    )
    phase: Optional[PhaseType] = Field(
        None,
        description="Phase this risk applies to",
    )


class TestPlan(BaseModel):
    """
    Master Test Plan - Single Source of Truth.

    Created at session start and updated after each phase completion.
    Contains all information about the penetration test scope, objectives,
    constraints, and progress.
    """

    plan_id: str = Field(
        default_factory=lambda: f"testplan-{uuid.uuid4().hex[:8]}",
        description="Unique plan identifier",
    )
    session_id: str = Field(
        ...,
        description="Session this plan belongs to",
    )
    version: int = Field(
        default=1,
        description="Plan version (incremented on each update)",
    )
    created_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="When the plan was created",
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="When the plan was last updated",
    )
    updated_by: str = Field(
        default="planner_agent",
        description="Who last updated the plan",
    )

    # Scope Summary
    scope_summary: str = Field(
        ...,
        description="Summary of the test scope",
    )
    target_description: str = Field(
        ...,
        description="Description of the target(s)",
    )

    # Objectives
    primary_objective: str = Field(
        ...,
        description="Primary objective of the test",
    )
    secondary_objectives: List[str] = Field(
        default_factory=list,
        description="Secondary objectives",
    )

    # Phase Sequence
    phase_sequence: List[PhaseObjective] = Field(
        default_factory=list,
        description="Ordered sequence of phases with objectives",
    )

    # Assumptions and Constraints
    assumptions: List[str] = Field(
        default_factory=list,
        description="Assumptions made in planning",
    )
    constraints: List[str] = Field(
        default_factory=list,
        description="Constraints on the test",
    )
    stop_conditions: List[str] = Field(
        default_factory=list,
        description="Conditions that will stop the test",
    )
    evidence_policy: str = Field(
        default="All operations will be logged. Evidence will be collected for all findings.",
        description="Policy for evidence collection",
    )

    # Questions and Risks
    open_questions: List[OpenQuestion] = Field(
        default_factory=list,
        description="Open questions to be resolved",
    )
    risks: List[TestPlanRisk] = Field(
        default_factory=list,
        description="Identified risks",
    )

    # Change Log
    change_log: List[PlanChangeEntry] = Field(
        default_factory=list,
        description="History of changes to this plan",
    )

    # Current State
    current_phase: Optional[PhaseType] = Field(
        None,
        description="Currently active phase",
    )
    overall_status: str = Field(
        default="initialized",
        description="Overall test status",
    )
    overall_risk_level: RiskLevel = Field(
        default=RiskLevel.MEDIUM,
        description="Overall risk level of the test",
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "plan_id": self.plan_id,
            "session_id": self.session_id,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
            "scope_summary": self.scope_summary,
            "target_description": self.target_description,
            "primary_objective": self.primary_objective,
            "secondary_objectives": self.secondary_objectives,
            "phase_sequence": [p.to_dict() for p in self.phase_sequence],
            "assumptions": self.assumptions,
            "constraints": self.constraints,
            "stop_conditions": self.stop_conditions,
            "evidence_policy": self.evidence_policy,
            "open_questions": [
                {
                    "question_id": q.question_id,
                    "question": q.question,
                    "context": q.context,
                    "priority": q.priority,
                    "resolved": q.resolved,
                    "resolution": q.resolution,
                    "resolved_at": q.resolved_at,
                }
                for q in self.open_questions
            ],
            "risks": [
                {
                    "risk_id": r.risk_id,
                    "description": r.description,
                    "likelihood": r.likelihood,
                    "impact": r.impact,
                    "mitigation": r.mitigation,
                    "phase": r.phase.value if r.phase else None,
                }
                for r in self.risks
            ],
            "change_log": [c.to_dict() for c in self.change_log],
            "current_phase": self.current_phase.value if self.current_phase else None,
            "overall_status": self.overall_status,
            "overall_risk_level": self.overall_risk_level.value,
        }

    def add_change(
        self,
        change_type: PlanChangeType,
        summary: str,
        reason: str,
        changed_by: str,
        previous_values: Optional[Dict] = None,
        new_values: Optional[Dict] = None,
        related_evidence_ids: Optional[List[str]] = None,
        related_finding_ids: Optional[List[str]] = None,
    ) -> PlanChangeEntry:
        """Add a change entry to the log."""
        self.version += 1
        self.updated_at = datetime.utcnow().isoformat() + "Z"
        self.updated_by = changed_by

        entry = PlanChangeEntry(
            change_type=change_type,
            summary=summary,
            reason=reason,
            changed_by=changed_by,
            previous_values=previous_values or {},
            new_values=new_values or {},
            related_evidence_ids=related_evidence_ids or [],
            related_finding_ids=related_finding_ids or [],
        )
        self.change_log.append(entry)
        return entry

    def update_phase_status(
        self,
        phase: PhaseType,
        status: PhaseStatus,
        changed_by: str,
        notes: Optional[str] = None,
    ) -> None:
        """Update the status of a phase."""
        for phase_obj in self.phase_sequence:
            if phase_obj.phase == phase:
                old_status = phase_obj.status
                phase_obj.status = status
                if notes:
                    phase_obj.notes = notes

                self.add_change(
                    change_type=PlanChangeType.PHASE_COMPLETION,
                    summary=f"Phase {phase.value} status changed to {status.value}",
                    reason=notes or "Phase status update",
                    changed_by=changed_by,
                    previous_values={"status": old_status.value},
                    new_values={"status": status.value},
                )
                break

    def get_next_phase(self) -> Optional[PhaseObjective]:
        """Get the next phase to execute."""
        for phase_obj in self.phase_sequence:
            if phase_obj.status == PhaseStatus.NOT_STARTED:
                return phase_obj
        return None

    def get_current_phase_objective(self) -> Optional[PhaseObjective]:
        """Get the current phase objective."""
        for phase_obj in self.phase_sequence:
            if phase_obj.status == PhaseStatus.IN_PROGRESS:
                return phase_obj
        return None

    def get_change_summary(self, since_version: int = 0) -> str:
        """Get summary of changes since a given version."""
        recent_changes = [
            c for c in self.change_log
            if c.change_id > f"change-{since_version:08d}"  # Simplified version check
        ]
        if not recent_changes:
            return "No recent changes."

        lines = ["### Recent Changes to Test Plan"]
        for change in recent_changes[-5:]:  # Last 5 changes
            lines.append(f"- [{change.change_type.value}] {change.summary}")
            lines.append(f"  Reason: {change.reason}")

        return "\n".join(lines)

    def to_human_display(self) -> str:
        """Format plan for human display."""
        lines = [
            f"# Test Plan v{self.version}",
            "",
            f"**Plan ID:** {self.plan_id}",
            f"**Last Updated:** {self.updated_at}",
            f"**Overall Status:** {self.overall_status}",
            f"**Risk Level:** {self.overall_risk_level.value.upper()}",
            "",
            "## Scope",
            self.scope_summary,
            "",
            "## Target",
            self.target_description,
            "",
            "## Objectives",
            f"**Primary:** {self.primary_objective}",
        ]

        if self.secondary_objectives:
            lines.append("**Secondary:**")
            for obj in self.secondary_objectives:
                lines.append(f"- {obj}")

        lines.extend([
            "",
            "## Phase Sequence",
        ])

        status_icons = {
            PhaseStatus.NOT_STARTED: "⬜",
            PhaseStatus.IN_PROGRESS: "🔄",
            PhaseStatus.COMPLETED: "✅",
            PhaseStatus.SKIPPED: "⏭️",
            PhaseStatus.BLOCKED: "🚫",
            PhaseStatus.FAILED: "❌",
        }

        for phase_obj in self.phase_sequence:
            icon = status_icons.get(phase_obj.status, "⬜")
            lines.append(f"{icon} **{phase_obj.phase.value.replace('_', ' ').title()}**")
            lines.append(f"   {phase_obj.objective}")

        if self.constraints:
            lines.extend([
                "",
                "## Constraints",
            ])
            for constraint in self.constraints:
                lines.append(f"- {constraint}")

        if self.open_questions:
            unresolved = [q for q in self.open_questions if not q.resolved]
            if unresolved:
                lines.extend([
                    "",
                    "## Open Questions",
                ])
                for q in unresolved:
                    lines.append(f"- [{q.priority}] {q.question}")

        return "\n".join(lines)

    def get_change_diff_display(self, since_version: Optional[int] = None) -> str:
        """Get display of changes since a version (for phase approval)."""
        if since_version is None:
            since_version = max(0, self.version - 2)

        relevant_changes = self.change_log[-3:] if self.change_log else []

        if not relevant_changes:
            return "No recent changes to the test plan."

        lines = ["### Test Plan Updates"]
        for change in relevant_changes:
            lines.append(f"- **{change.change_type.value.replace('_', ' ').title()}:** {change.summary}")
            if change.reason:
                lines.append(f"  _Reason: {change.reason}_")

        return "\n".join(lines)


def create_initial_test_plan(
    session_id: str,
    target_description: str,
    scope_summary: str,
    primary_objective: str = "Identify and verify security vulnerabilities in the target system",
) -> TestPlan:
    """
    Create an initial test plan for a new session.

    Args:
        session_id: Session identifier.
        target_description: Description of the target.
        scope_summary: Summary of the test scope.
        primary_objective: Primary objective of the test.

    Returns:
        Initialized TestPlan.
    """
    plan = TestPlan(
        session_id=session_id,
        scope_summary=scope_summary,
        target_description=target_description,
        primary_objective=primary_objective,
        secondary_objectives=[
            "Map the attack surface of the target",
            "Identify potential entry points",
            "Assess the severity of discovered vulnerabilities",
            "Document findings with reproducible evidence",
        ],
        phase_sequence=[
            PhaseObjective(
                phase=PhaseType.RECONNAISSANCE,
                objective="Discover target infrastructure, services, and technologies",
                success_criteria=[
                    "Open ports identified",
                    "Services enumerated",
                    "Technology stack detected",
                ],
                priority=1,
            ),
            PhaseObjective(
                phase=PhaseType.ENUMERATION,
                objective="Gather detailed information about discovered services",
                success_criteria=[
                    "Service versions identified",
                    "Web application entry points mapped",
                    "Authentication mechanisms identified",
                ],
                priority=2,
            ),
            PhaseObjective(
                phase=PhaseType.VULNERABILITY_ASSESSMENT,
                objective="Identify potential vulnerabilities in discovered services",
                success_criteria=[
                    "CVE candidates identified",
                    "Vulnerability severity assessed",
                    "Exploitation feasibility evaluated",
                ],
                priority=3,
            ),
            PhaseObjective(
                phase=PhaseType.EXPLOITATION,
                objective="Verify exploitability of identified vulnerabilities",
                success_criteria=[
                    "Exploitation attempts documented",
                    "Proof of access obtained where applicable",
                    "Impact demonstrated",
                ],
                priority=4,
            ),
            PhaseObjective(
                phase=PhaseType.REPORTING,
                objective="Document findings and recommendations",
                success_criteria=[
                    "All findings documented with evidence",
                    "CVSS scores assigned",
                    "Remediation recommendations provided",
                ],
                priority=5,
            ),
        ],
        assumptions=[
            "Target is within authorized scope",
            "Network connectivity to target is available",
            "Test window is sufficient for planned activities",
        ],
        constraints=[
            "Operations must stay within defined scope",
            "Destructive operations are not permitted",
            "All operations must be logged for audit",
        ],
        stop_conditions=[
            "Scope violation detected",
            "Critical error without recovery path",
            "Human stop command received",
            "Session timeout exceeded",
        ],
    )

    # Add initial change log entry
    plan.change_log.append(PlanChangeEntry(
        change_type=PlanChangeType.INITIAL_CREATION,
        summary="Test plan created",
        reason="Session initialization",
        changed_by="planner_agent",
    ))

    return plan
