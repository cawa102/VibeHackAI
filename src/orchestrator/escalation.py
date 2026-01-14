"""
Policy Escalation for PentestAgent.

Implements FR-3: When operations deviate from approved plan,
stop and request additional approval before continuing.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from ..schemas.phase_brief import PhaseBrief, PhaseType, RiskLevel, PlannedAction
from ..schemas.approval_log import ApprovalLog, ApprovalDecision, ApprovalType

if TYPE_CHECKING:
    from ..storage.state_store import StateStore


class EscalationType(str, Enum):
    """Types of escalation triggers."""
    SCOPE_DEVIATION = "scope_deviation"
    RISK_INCREASE = "risk_increase"
    POLICY_VIOLATION = "policy_violation"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNEXPECTED_ACCESS = "unexpected_access"
    DATA_LIMIT_EXCEEDED = "data_limit_exceeded"
    TOOL_RESTRICTION = "tool_restriction"
    AUTHENTICATION_REQUIRED = "authentication_required"


class EscalationSeverity(str, Enum):
    """Severity levels for escalations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EscalationStatus(str, Enum):
    """Status of escalation request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ALTERNATIVE_CHOSEN = "alternative_chosen"


@dataclass
class EscalationContext:
    """Context information for an escalation."""
    current_phase: PhaseType
    current_action: str
    original_plan_action: Optional[str] = None
    deviation_details: Optional[str] = None
    affected_target: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)


@dataclass
class EscalationRequest:
    """Request for escalation approval."""
    escalation_id: str
    session_id: str
    escalation_type: EscalationType
    severity: EscalationSeverity
    title: str
    description: str
    context: EscalationContext
    proposed_action: str
    alternatives: List[str]
    risk_assessment: str
    requires_approval: bool = True
    status: EscalationStatus = EscalationStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    responded_at: Optional[str] = None
    responded_by: Optional[str] = None
    response_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "escalation_id": self.escalation_id,
            "session_id": self.session_id,
            "escalation_type": self.escalation_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "context": {
                "current_phase": self.context.current_phase.value,
                "current_action": self.context.current_action,
                "original_plan_action": self.context.original_plan_action,
                "deviation_details": self.context.deviation_details,
                "affected_target": self.context.affected_target,
                "evidence_ids": self.context.evidence_ids,
            },
            "proposed_action": self.proposed_action,
            "alternatives": self.alternatives,
            "risk_assessment": self.risk_assessment,
            "requires_approval": self.requires_approval,
            "status": self.status.value,
            "created_at": self.created_at,
            "responded_at": self.responded_at,
            "responded_by": self.responded_by,
            "response_notes": self.response_notes,
        }

    def to_human_display(self) -> str:
        """Format for human display."""
        lines = [
            "=" * 60,
            f"ESCALATION: {self.title}",
            "=" * 60,
            "",
            f"**Type:** {self.escalation_type.value.replace('_', ' ').title()}",
            f"**Severity:** {self.severity.value.upper()}",
            f"**Phase:** {self.context.current_phase.value.replace('_', ' ').title()}",
            "",
            "### Description",
            self.description,
            "",
            "### Current Context",
            f"- Current Action: {self.context.current_action}",
        ]

        if self.context.original_plan_action:
            lines.append(f"- Original Planned Action: {self.context.original_plan_action}")
        if self.context.deviation_details:
            lines.append(f"- Deviation: {self.context.deviation_details}")
        if self.context.affected_target:
            lines.append(f"- Affected Target: {self.context.affected_target}")

        lines.extend([
            "",
            "### Proposed Action",
            self.proposed_action,
            "",
            "### Risk Assessment",
            self.risk_assessment,
            "",
        ])

        if self.alternatives:
            lines.append("### Alternatives")
            for i, alt in enumerate(self.alternatives, 1):
                lines.append(f"{i}. {alt}")
            lines.append("")

        lines.extend([
            "-" * 60,
            "Options:",
            "  [A] Approve proposed action",
            "  [R] Reject and stop operation",
        ])

        if self.alternatives:
            for i in range(len(self.alternatives)):
                lines.append(f"  [{i+1}] Choose alternative {i+1}")

        lines.append("-" * 60)

        return "\n".join(lines)


@dataclass
class EscalationResponse:
    """Response to escalation request."""
    escalation_id: str
    approved: bool
    chosen_alternative: Optional[int] = None  # Index of chosen alternative
    responded_by: str = "user"
    notes: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


# Type for escalation callback
EscalationCallback = Callable[[EscalationRequest], EscalationResponse]


class PolicyEscalationManager:
    """
    Manages policy escalations during penetration testing.

    Implements FR-3: Detects deviations from approved plan and
    requests additional approval before proceeding.
    """

    def __init__(
        self,
        session_id: str,
        state_store: Optional["StateStore"] = None,
        escalation_callback: Optional[EscalationCallback] = None,
    ):
        """
        Initialize escalation manager.

        Args:
            session_id: Session identifier.
            state_store: State store for persistence.
            escalation_callback: Callback for escalation approval.
        """
        self.session_id = session_id
        self.state_store = state_store
        self.escalation_callback = escalation_callback

        self._pending_escalations: Dict[str, EscalationRequest] = {}
        self._escalation_history: List[EscalationRequest] = []

        # Policy thresholds
        self._rate_limits: Dict[str, int] = {
            "requests_per_minute": 60,
            "scans_per_hour": 10,
            "exploits_per_session": 5,
        }
        self._data_limits: Dict[str, int] = {
            "max_file_read_bytes": 4096,
            "max_total_data_bytes": 20480,
        }

    def check_deviation(
        self,
        current_action: str,
        approved_brief: PhaseBrief,
        context: Dict[str, Any],
    ) -> Optional[EscalationRequest]:
        """
        Check if current action deviates from approved plan.

        Args:
            current_action: Description of current action.
            approved_brief: The approved PhaseBrief.
            context: Current execution context.

        Returns:
            EscalationRequest if deviation detected, None otherwise.
        """
        # Check if action matches any planned actions
        action_matched = False
        for planned in approved_brief.planned_actions:
            if self._action_matches(current_action, planned):
                action_matched = True
                break

        if not action_matched:
            return self._create_deviation_escalation(
                current_action,
                approved_brief,
                context,
            )

        return None

    def _action_matches(self, current: str, planned: PlannedAction) -> bool:
        """Check if current action matches a planned action."""
        current_lower = current.lower()
        planned_lower = planned.summary.lower()

        # Simple keyword matching
        keywords = planned_lower.split()
        match_count = sum(1 for kw in keywords if kw in current_lower)

        return match_count >= len(keywords) * 0.5

    def _create_deviation_escalation(
        self,
        current_action: str,
        approved_brief: PhaseBrief,
        context: Dict[str, Any],
    ) -> EscalationRequest:
        """Create escalation for plan deviation."""
        planned_actions = [a.summary for a in approved_brief.planned_actions]

        return EscalationRequest(
            escalation_id=f"esc-{uuid.uuid4().hex[:8]}",
            session_id=self.session_id,
            escalation_type=EscalationType.SCOPE_DEVIATION,
            severity=EscalationSeverity.MEDIUM,
            title="Action Deviation from Approved Plan",
            description=(
                f"The current action '{current_action}' was not included in the "
                f"approved phase brief. Approval is required to proceed."
            ),
            context=EscalationContext(
                current_phase=approved_brief.phase,
                current_action=current_action,
                original_plan_action=", ".join(planned_actions),
                deviation_details="Action not in approved plan",
                affected_target=context.get("target"),
            ),
            proposed_action=f"Proceed with: {current_action}",
            alternatives=[
                "Skip this action and continue with approved plan",
                "Stop and revise the test plan",
            ],
            risk_assessment="Medium risk - action not pre-approved but may be necessary for testing.",
        )

    def check_rate_limit(
        self,
        operation_type: str,
        current_count: int,
        phase: PhaseType,
    ) -> Optional[EscalationRequest]:
        """
        Check if rate limit is exceeded.

        Args:
            operation_type: Type of operation.
            current_count: Current count of operations.
            phase: Current phase.

        Returns:
            EscalationRequest if limit exceeded, None otherwise.
        """
        limit_key = f"{operation_type}_per_minute"
        limit = self._rate_limits.get(limit_key)

        if limit and current_count >= limit:
            return EscalationRequest(
                escalation_id=f"esc-{uuid.uuid4().hex[:8]}",
                session_id=self.session_id,
                escalation_type=EscalationType.RATE_LIMIT_EXCEEDED,
                severity=EscalationSeverity.MEDIUM,
                title="Rate Limit Exceeded",
                description=(
                    f"The operation rate limit for {operation_type} has been reached "
                    f"({current_count}/{limit}). This may trigger security alerts."
                ),
                context=EscalationContext(
                    current_phase=phase,
                    current_action=f"Rate limit check for {operation_type}",
                ),
                proposed_action="Continue with increased rate (may trigger alerts)",
                alternatives=[
                    "Wait and resume at normal rate",
                    "Reduce operation intensity",
                    "Skip remaining operations of this type",
                ],
                risk_assessment="Medium risk - high request rate may trigger IDS/IPS alerts.",
            )

        return None

    def check_data_limit(
        self,
        bytes_requested: int,
        bytes_already_read: int,
        file_path: str,
        phase: PhaseType,
    ) -> Optional[EscalationRequest]:
        """
        Check if data read limit is exceeded.

        Args:
            bytes_requested: Bytes requested to read.
            bytes_already_read: Total bytes already read.
            file_path: Path of file being read.
            phase: Current phase.

        Returns:
            EscalationRequest if limit exceeded, None otherwise.
        """
        max_file = self._data_limits.get("max_file_read_bytes", 4096)
        max_total = self._data_limits.get("max_total_data_bytes", 20480)

        if bytes_requested > max_file:
            return EscalationRequest(
                escalation_id=f"esc-{uuid.uuid4().hex[:8]}",
                session_id=self.session_id,
                escalation_type=EscalationType.DATA_LIMIT_EXCEEDED,
                severity=EscalationSeverity.HIGH,
                title="File Read Size Limit Exceeded",
                description=(
                    f"Requested to read {bytes_requested} bytes from {file_path}, "
                    f"but limit is {max_file} bytes per file."
                ),
                context=EscalationContext(
                    current_phase=phase,
                    current_action=f"Read file: {file_path}",
                    affected_target=file_path,
                ),
                proposed_action=f"Read only first {max_file} bytes",
                alternatives=[
                    "Skip this file read",
                    "Use a different proof-of-access method",
                ],
                risk_assessment="High risk - reading more data than necessary for proof.",
            )

        if bytes_already_read + bytes_requested > max_total:
            return EscalationRequest(
                escalation_id=f"esc-{uuid.uuid4().hex[:8]}",
                session_id=self.session_id,
                escalation_type=EscalationType.DATA_LIMIT_EXCEEDED,
                severity=EscalationSeverity.HIGH,
                title="Total Data Read Limit Exceeded",
                description=(
                    f"Total data read would exceed limit: {bytes_already_read} + "
                    f"{bytes_requested} > {max_total} bytes."
                ),
                context=EscalationContext(
                    current_phase=phase,
                    current_action=f"Read file: {file_path}",
                ),
                proposed_action="Proceed with reduced read size",
                alternatives=[
                    "Skip remaining file reads",
                    "Complete testing with current evidence",
                ],
                risk_assessment="High risk - approaching data exfiltration thresholds.",
            )

        return None

    def check_risk_increase(
        self,
        new_risk_level: RiskLevel,
        approved_risk_level: RiskLevel,
        action_description: str,
        phase: PhaseType,
    ) -> Optional[EscalationRequest]:
        """
        Check if risk level has increased beyond approved level.

        Args:
            new_risk_level: New assessed risk level.
            approved_risk_level: Originally approved risk level.
            action_description: Description of the action.
            phase: Current phase.

        Returns:
            EscalationRequest if risk increased, None otherwise.
        """
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]

        if risk_order.index(new_risk_level) > risk_order.index(approved_risk_level):
            return EscalationRequest(
                escalation_id=f"esc-{uuid.uuid4().hex[:8]}",
                session_id=self.session_id,
                escalation_type=EscalationType.RISK_INCREASE,
                severity=EscalationSeverity.HIGH,
                title="Risk Level Increase Detected",
                description=(
                    f"The planned action '{action_description}' has a higher risk level "
                    f"({new_risk_level.value}) than originally approved ({approved_risk_level.value})."
                ),
                context=EscalationContext(
                    current_phase=phase,
                    current_action=action_description,
                ),
                proposed_action=f"Proceed with {new_risk_level.value} risk action",
                alternatives=[
                    "Find a lower-risk alternative approach",
                    "Skip this action",
                    "Stop and reassess the test plan",
                ],
                risk_assessment=f"Risk increased from {approved_risk_level.value} to {new_risk_level.value}.",
            )

        return None

    def request_escalation_approval(
        self,
        escalation: EscalationRequest,
    ) -> EscalationResponse:
        """
        Request approval for an escalation.

        Args:
            escalation: The escalation request.

        Returns:
            EscalationResponse with decision.
        """
        self._pending_escalations[escalation.escalation_id] = escalation

        # Persist
        if self.state_store:
            self.state_store.append_jsonl(
                "escalations.jsonl",
                escalation.to_dict(),
            )

        # Request via callback
        if self.escalation_callback:
            response = self.escalation_callback(escalation)
            self._record_response(escalation, response)
            return response

        # No callback - reject
        response = EscalationResponse(
            escalation_id=escalation.escalation_id,
            approved=False,
            responded_by="system",
            notes="No escalation callback configured - auto-rejected",
        )
        self._record_response(escalation, response)
        return response

    def _record_response(
        self,
        escalation: EscalationRequest,
        response: EscalationResponse,
    ) -> None:
        """Record escalation response."""
        escalation.responded_at = response.timestamp
        escalation.responded_by = response.responded_by
        escalation.response_notes = response.notes

        if response.approved:
            escalation.status = EscalationStatus.APPROVED
        elif response.chosen_alternative is not None:
            escalation.status = EscalationStatus.ALTERNATIVE_CHOSEN
        else:
            escalation.status = EscalationStatus.REJECTED

        # Move to history
        if escalation.escalation_id in self._pending_escalations:
            del self._pending_escalations[escalation.escalation_id]
        self._escalation_history.append(escalation)

        # Create audit log
        if self.state_store:
            log_entry = ApprovalLog(
                session_id=self.session_id,
                approval_type=ApprovalType.PHASE_ESCALATION,
                phase=escalation.context.current_phase.value,
                request_summary=f"Escalation: {escalation.title}",
                decision=ApprovalDecision.APPROVED if response.approved else ApprovalDecision.REJECTED,
                approved_by=response.responded_by,
                notes=response.notes,
                context={"escalation_type": escalation.escalation_type.value},
            )
            self.state_store.append_jsonl("approval_log.jsonl", log_entry.to_dict())

    def get_escalation_history(self) -> List[EscalationRequest]:
        """Get escalation history."""
        return self._escalation_history

    def get_pending_escalations(self) -> List[EscalationRequest]:
        """Get pending escalations."""
        return list(self._pending_escalations.values())

    def update_limits(
        self,
        rate_limits: Optional[Dict[str, int]] = None,
        data_limits: Optional[Dict[str, int]] = None,
    ) -> None:
        """Update policy limits."""
        if rate_limits:
            self._rate_limits.update(rate_limits)
        if data_limits:
            self._data_limits.update(data_limits)
