"""
Phase Approval Flow for PentestAgent.

Implements FR-1: Phase boundary approval before each phase starts.
Human approves at phase transitions, not individual commands.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from ..schemas.phase_brief import PhaseBrief, PhaseType, RiskLevel, PlannedAction, SafetyConstraint
from ..schemas.approval_log import ApprovalLog, ApprovalDecision, ApprovalType
from ..schemas.test_plan import TestPlan

if TYPE_CHECKING:
    from ..storage.state_store import StateStore


class PhaseApprovalStatus(str, Enum):
    """Status of phase approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEFERRED = "deferred"
    TIMEOUT = "timeout"


@dataclass
class PhaseApprovalRequest:
    """Request for phase approval."""
    request_id: str
    session_id: str
    phase: PhaseType
    brief: PhaseBrief
    test_plan_diff: Optional[str] = None  # Changes since last approval
    status: PhaseApprovalStatus = PhaseApprovalStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    responded_at: Optional[str] = None
    responded_by: Optional[str] = None
    response_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "phase": self.phase.value,
            "brief": self.brief.to_dict(),
            "test_plan_diff": self.test_plan_diff,
            "status": self.status.value,
            "created_at": self.created_at,
            "responded_at": self.responded_at,
            "responded_by": self.responded_by,
            "response_notes": self.response_notes,
        }


@dataclass
class PhaseApprovalResponse:
    """Response to phase approval request."""
    request_id: str
    approved: bool
    responded_by: str
    notes: Optional[str] = None
    modifications: Optional[Dict[str, Any]] = None  # User modifications to plan
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


# Type for approval callback
PhaseApprovalCallback = Callable[[PhaseApprovalRequest], PhaseApprovalResponse]


class PhaseApprovalGate:
    """
    Gate for phase-level approvals.

    Implements FR-1: Human approves phase transitions, not individual commands.
    Each phase must be approved before execution begins.
    """

    def __init__(
        self,
        session_id: str,
        state_store: Optional["StateStore"] = None,
        approval_callback: Optional[PhaseApprovalCallback] = None,
    ):
        """
        Initialize phase approval gate.

        Args:
            session_id: Session identifier.
            state_store: State store for persistence.
            approval_callback: Callback to request human approval.
        """
        self.session_id = session_id
        self.state_store = state_store
        self.approval_callback = approval_callback

        self._pending_requests: Dict[str, PhaseApprovalRequest] = {}
        self._approval_history: List[ApprovalLog] = []
        self._last_approved_phase: Optional[PhaseType] = None

    def create_phase_brief(
        self,
        phase: PhaseType,
        test_plan: TestPlan,
        previous_phase_result: Optional[Dict[str, Any]] = None,
    ) -> PhaseBrief:
        """
        Create a PhaseBrief for human presentation.

        Args:
            phase: Phase to create brief for.
            test_plan: Current test plan.
            previous_phase_result: Results from previous phase.

        Returns:
            PhaseBrief for human approval.
        """
        # Get phase objective from test plan
        phase_objective = None
        for obj in test_plan.phase_sequence:
            if obj.phase == phase:
                phase_objective = obj
                break

        objective = phase_objective.objective if phase_objective else f"Execute {phase.value} phase"

        # Generate rationale based on previous results
        if previous_phase_result:
            rationale = self._generate_rationale(phase, previous_phase_result)
        else:
            rationale = f"Starting {phase.value} phase as part of the penetration test plan."

        # Create planned actions based on phase type
        planned_actions = self._generate_planned_actions(phase, test_plan)

        # Create safety constraints
        safety_constraints = self._generate_safety_constraints(phase, test_plan)

        # Determine risk level
        risk_level = self._determine_risk_level(phase)

        # Create brief
        brief = PhaseBrief(
            phase=phase,
            title=f"{phase.value.replace('_', ' ').title()} Phase",
            objective=objective,
            rationale=rationale,
            planned_actions=planned_actions,
            risk_notes=self._generate_risk_notes(phase),
            safety_constraints=safety_constraints,
            expected_outcomes=self._generate_expected_outcomes(phase),
            overall_risk_level=risk_level,
            requires_phase_approval=True,
        )

        return brief

    def _generate_rationale(
        self,
        phase: PhaseType,
        previous_result: Dict[str, Any],
    ) -> str:
        """Generate rationale based on previous phase results."""
        rationales = {
            PhaseType.RECONNAISSANCE: "Initial information gathering to map the target's attack surface.",
            PhaseType.ENUMERATION: f"Previous reconnaissance identified services. Now gathering detailed information about discovered components.",
            PhaseType.VULNERABILITY_ASSESSMENT: f"Enumeration completed. Searching for vulnerabilities in identified services and technologies.",
            PhaseType.EXPLOITATION: f"Vulnerabilities identified. Proceeding to verify exploitability with human approval for each attempt.",
            PhaseType.POST_EXPLOITATION: f"Initial access obtained. Documenting access level and gathering additional evidence.",
            PhaseType.REPORTING: "Testing phases complete. Compiling findings into final report.",
        }
        return rationales.get(phase, f"Proceeding with {phase.value} phase based on previous results.")

    def _generate_planned_actions(
        self,
        phase: PhaseType,
        test_plan: TestPlan,
    ) -> List[PlannedAction]:
        """Generate planned actions for a phase (natural language, NO commands)."""
        actions_by_phase = {
            PhaseType.RECONNAISSANCE: [
                PlannedAction(
                    summary="Perform network scanning to identify open ports and services",
                    objective="Discover network-accessible services",
                    target_description="Target IP address and common port ranges",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Detect technologies and software versions",
                    objective="Identify technology stack for vulnerability research",
                    target_description="Discovered web services and applications",
                    risk_level=RiskLevel.LOW,
                ),
            ],
            PhaseType.ENUMERATION: [
                PlannedAction(
                    summary="Gather detailed service information",
                    objective="Enumerate service configurations and versions",
                    target_description="Services discovered during reconnaissance",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Map web application structure",
                    objective="Identify entry points and application flow",
                    target_description="Web applications on target",
                    risk_level=RiskLevel.MEDIUM,
                ),
            ],
            PhaseType.VULNERABILITY_ASSESSMENT: [
                PlannedAction(
                    summary="Search vulnerability databases for known issues",
                    objective="Identify CVEs and known vulnerabilities",
                    target_description="Identified software and versions",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Assess vulnerability applicability",
                    objective="Determine which vulnerabilities may affect the target",
                    target_description="Discovered services and configurations",
                    risk_level=RiskLevel.MEDIUM,
                ),
            ],
            PhaseType.EXPLOITATION: [
                PlannedAction(
                    summary="Verify vulnerability exploitability",
                    objective="Confirm vulnerabilities can be exploited",
                    target_description="Identified vulnerability candidates",
                    risk_level=RiskLevel.HIGH,
                    requires_approval=True,
                ),
                PlannedAction(
                    summary="Obtain proof of access",
                    objective="Demonstrate successful exploitation with minimal impact",
                    target_description="Exploitable vulnerabilities",
                    risk_level=RiskLevel.HIGH,
                    requires_approval=True,
                ),
            ],
            PhaseType.REPORTING: [
                PlannedAction(
                    summary="Compile findings into structured report",
                    objective="Document all findings with evidence",
                    target_description="All collected evidence and findings",
                    risk_level=RiskLevel.LOW,
                ),
            ],
        }
        return actions_by_phase.get(phase, [])

    def _generate_safety_constraints(
        self,
        phase: PhaseType,
        test_plan: TestPlan,
    ) -> List[SafetyConstraint]:
        """Generate safety constraints for a phase."""
        constraints = [
            SafetyConstraint(
                description="Operations limited to defined scope",
                constraint_type="scope",
                value="in_scope_targets_only",
            ),
            SafetyConstraint(
                description="All operations logged for audit",
                constraint_type="audit",
                value="full_logging",
            ),
        ]

        if phase == PhaseType.EXPLOITATION:
            constraints.extend([
                SafetyConstraint(
                    description="File read limited by Proof-of-Access policy",
                    constraint_type="data_access",
                    value="max_4096_bytes_per_file",
                ),
                SafetyConstraint(
                    description="No destructive operations",
                    constraint_type="safety",
                    value="read_only_proof",
                ),
            ])

        return constraints

    def _determine_risk_level(self, phase: PhaseType) -> RiskLevel:
        """Determine risk level for a phase."""
        risk_map = {
            PhaseType.PLANNING: RiskLevel.LOW,
            PhaseType.RECONNAISSANCE: RiskLevel.LOW,
            PhaseType.ENUMERATION: RiskLevel.MEDIUM,
            PhaseType.VULNERABILITY_ASSESSMENT: RiskLevel.MEDIUM,
            PhaseType.EXPLOITATION: RiskLevel.HIGH,
            PhaseType.POST_EXPLOITATION: RiskLevel.HIGH,
            PhaseType.REPORTING: RiskLevel.LOW,
        }
        return risk_map.get(phase, RiskLevel.MEDIUM)

    def _generate_risk_notes(self, phase: PhaseType) -> List[str]:
        """Generate risk notes for a phase."""
        notes_by_phase = {
            PhaseType.RECONNAISSANCE: [
                "Network scanning may be detected by security systems",
                "Rate limiting applied to avoid triggering alerts",
            ],
            PhaseType.ENUMERATION: [
                "Active probing may trigger security monitoring",
                "Web crawling limited to target application",
            ],
            PhaseType.VULNERABILITY_ASSESSMENT: [
                "Vulnerability checks are non-invasive",
                "No exploitation attempts at this phase",
            ],
            PhaseType.EXPLOITATION: [
                "Exploitation requires explicit approval for each attempt",
                "Proof-of-access limited to minimal file read",
                "All payloads are for verification only",
            ],
        }
        return notes_by_phase.get(phase, [])

    def _generate_expected_outcomes(self, phase: PhaseType) -> List[str]:
        """Generate expected outcomes for a phase."""
        outcomes_by_phase = {
            PhaseType.RECONNAISSANCE: [
                "List of open ports and services",
                "Technology stack identification",
                "Initial attack surface map",
            ],
            PhaseType.ENUMERATION: [
                "Detailed service configurations",
                "Web application structure",
                "Potential entry points identified",
            ],
            PhaseType.VULNERABILITY_ASSESSMENT: [
                "List of applicable CVEs",
                "Vulnerability severity assessments",
                "Exploitation feasibility ratings",
            ],
            PhaseType.EXPLOITATION: [
                "Proof of vulnerability exploitation",
                "Access level demonstration",
                "Evidence for reporting",
            ],
            PhaseType.REPORTING: [
                "Complete penetration test report",
                "CVSS-scored findings",
                "Remediation recommendations",
            ],
        }
        return outcomes_by_phase.get(phase, [])

    def request_phase_approval(
        self,
        phase: PhaseType,
        test_plan: TestPlan,
        previous_phase_result: Optional[Dict[str, Any]] = None,
    ) -> PhaseApprovalResponse:
        """
        Request approval for a phase.

        Args:
            phase: Phase to request approval for.
            test_plan: Current test plan.
            previous_phase_result: Results from previous phase.

        Returns:
            PhaseApprovalResponse with decision.
        """
        # Create brief
        brief = self.create_phase_brief(phase, test_plan, previous_phase_result)

        # Get test plan diff
        test_plan_diff = test_plan.get_change_diff_display()

        # Create request
        request = PhaseApprovalRequest(
            request_id=f"phase-approval-{uuid.uuid4().hex[:8]}",
            session_id=self.session_id,
            phase=phase,
            brief=brief,
            test_plan_diff=test_plan_diff,
        )

        self._pending_requests[request.request_id] = request

        # Persist request
        if self.state_store:
            self.state_store.append_jsonl(
                "phase_approval_requests.jsonl",
                request.to_dict(),
            )

        # Request approval via callback
        if self.approval_callback:
            response = self.approval_callback(request)
            self._record_response(request, response)
            return response

        # No callback - reject for safety
        response = PhaseApprovalResponse(
            request_id=request.request_id,
            approved=False,
            responded_by="system",
            notes="No approval callback configured - auto-rejected for safety",
        )
        self._record_response(request, response)
        return response

    def _record_response(
        self,
        request: PhaseApprovalRequest,
        response: PhaseApprovalResponse,
    ) -> None:
        """Record approval response."""
        request.responded_at = response.timestamp
        request.responded_by = response.responded_by
        request.response_notes = response.notes

        if response.approved:
            request.status = PhaseApprovalStatus.APPROVED
            self._last_approved_phase = request.phase
        else:
            request.status = PhaseApprovalStatus.REJECTED

        # Remove from pending
        if request.request_id in self._pending_requests:
            del self._pending_requests[request.request_id]

        # Create audit log entry
        decision = ApprovalDecision.APPROVED if response.approved else ApprovalDecision.REJECTED
        log_entry = ApprovalLog(
            session_id=self.session_id,
            approval_type=ApprovalType.PHASE_START,
            phase=request.phase.value,
            brief_id=request.brief.brief_id,
            request_summary=f"Phase {request.phase.value} approval: {request.brief.title}",
            decision=decision,
            approved_by=response.responded_by,
            notes=response.notes,
        )
        self._approval_history.append(log_entry)

        # Persist
        if self.state_store:
            self.state_store.append_jsonl(
                "approval_log.jsonl",
                log_entry.to_dict(),
            )

    def get_approval_history(self) -> List[ApprovalLog]:
        """Get approval history."""
        return self._approval_history

    def get_pending_requests(self) -> List[PhaseApprovalRequest]:
        """Get pending approval requests."""
        return list(self._pending_requests.values())

    def is_phase_approved(self, phase: PhaseType) -> bool:
        """Check if a phase has been approved."""
        for log in self._approval_history:
            if log.phase == phase.value and log.decision == ApprovalDecision.APPROVED:
                return True
        return False

    def get_last_approved_phase(self) -> Optional[PhaseType]:
        """Get the last approved phase."""
        return self._last_approved_phase


def create_phase_approval_display(request: PhaseApprovalRequest) -> str:
    """
    Create human-readable display for phase approval request.

    This is what the user sees - natural language only, NO commands.
    """
    lines = [
        "=" * 60,
        "PHASE APPROVAL REQUIRED",
        "=" * 60,
        "",
        request.brief.to_human_display(),
        "",
    ]

    if request.test_plan_diff:
        lines.extend([
            request.test_plan_diff,
            "",
        ])

    lines.extend([
        "-" * 60,
        "Options:",
        "  [A] Approve and proceed",
        "  [R] Reject and stop",
        "  [D] Defer (hold for later)",
        "-" * 60,
    ])

    return "\n".join(lines)
