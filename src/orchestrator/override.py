"""
Override Management for PentestAgent.

Implements FR-4: Human has absolute authority to override agent stops,
with full audit trail and defined non-overridable boundaries.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from ..schemas.approval_log import (
    OverrideLog,
    OverrideCategory,
    OverrideStatus,
    StopReport,
    can_override_stop,
    NON_OVERRIDABLE_CATEGORIES,
)

if TYPE_CHECKING:
    from ..storage.state_store import StateStore


class StopCategory(str, Enum):
    """Categories of agent stops."""
    SAFETY_POLICY = "safety_policy"
    SCOPE_VIOLATION = "scope_violation"
    RATE_LIMIT = "rate_limit"
    ERROR_THRESHOLD = "error_threshold"
    DATA_LIMIT = "data_limit"
    TOOL_RESTRICTION = "tool_restriction"
    # Non-overridable
    DESTRUCTIVE_OPERATION = "destructive_operation"
    OUT_OF_SCOPE_TARGET = "out_of_scope_target"
    MALWARE_CREATION = "malware_creation"


@dataclass
class OverrideRequest:
    """Request for human override of a stop."""
    override_id: str
    session_id: str
    stop_report: StopReport
    proposed_action: str
    risk_acknowledgment: str
    override_scope: Dict[str, Any]
    status: OverrideStatus = OverrideStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "override_id": self.override_id,
            "session_id": self.session_id,
            "stop_report": self.stop_report.to_dict(),
            "proposed_action": self.proposed_action,
            "risk_acknowledgment": self.risk_acknowledgment,
            "override_scope": self.override_scope,
            "status": self.status.value,
            "created_at": self.created_at,
        }


@dataclass
class OverrideDecision:
    """Human decision on override request."""
    override_id: str
    approved: bool
    responded_by: str
    reason: str
    scope_modifications: Optional[Dict[str, Any]] = None
    expiry_minutes: Optional[int] = None  # How long override is valid
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


# Type for override callback
OverrideCallback = Callable[[OverrideRequest], OverrideDecision]


class OverrideManager:
    """
    Manages override requests and decisions.

    Implements FR-4: Human absolute authority with audit trail.
    """

    def __init__(
        self,
        session_id: str,
        state_store: Optional["StateStore"] = None,
        override_callback: Optional[OverrideCallback] = None,
    ):
        """
        Initialize override manager.

        Args:
            session_id: Session identifier.
            state_store: State store for persistence.
            override_callback: Callback for override decisions.
        """
        self.session_id = session_id
        self.state_store = state_store
        self.override_callback = override_callback

        self._active_overrides: Dict[str, OverrideLog] = {}
        self._override_history: List[OverrideLog] = []

    def report_stop(
        self,
        phase: str,
        agent: str,
        stop_reason: str,
        stop_category: str,
        alternatives: Optional[List[str]] = None,
        impact_if_continue: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> StopReport:
        """
        Report an agent stop to human.

        Args:
            phase: Current phase.
            agent: Agent that stopped.
            stop_reason: Why the agent stopped.
            stop_category: Category of stop.
            alternatives: Alternative approaches.
            impact_if_continue: Impact if override granted.
            context: Additional context.

        Returns:
            StopReport for human review.
        """
        can_override = can_override_stop(stop_category)

        override_category = None
        if can_override:
            # Map stop category to override category
            category_map = {
                "safety_policy": OverrideCategory.SAFETY_POLICY,
                "scope_violation": OverrideCategory.SCOPE_BOUNDARY,
                "rate_limit": OverrideCategory.RATE_LIMIT,
                "data_limit": OverrideCategory.DATA_ACCESS_LIMIT,
                "tool_restriction": OverrideCategory.TOOL_RESTRICTION,
                "exploitation_limit": OverrideCategory.EXPLOITATION_LIMIT,
            }
            override_category = category_map.get(stop_category.lower())

        report = StopReport(
            session_id=self.session_id,
            phase=phase,
            agent=agent,
            stop_reason=stop_reason,
            stop_category=stop_category,
            can_override=can_override,
            override_category=override_category,
            alternatives=alternatives or [],
            impact_if_continue=impact_if_continue or "Unknown impact",
            recommendation=self._generate_recommendation(stop_category, can_override),
            context=context or {},
        )

        # Persist stop report
        if self.state_store:
            self.state_store.append_jsonl(
                "stop_reports.jsonl",
                report.to_dict(),
            )

        return report

    def _generate_recommendation(
        self,
        stop_category: str,
        can_override: bool,
    ) -> str:
        """Generate recommendation based on stop category."""
        if not can_override:
            return (
                "This stop CANNOT be overridden. The operation is prohibited by "
                "security policy. Please choose an alternative approach."
            )

        recommendations = {
            "safety_policy": "Consider the risks carefully before overriding safety policies.",
            "rate_limit": "Waiting may avoid triggering security alerts.",
            "data_limit": "Only override if the additional data is essential for proof.",
            "tool_restriction": "Ensure the restricted tool is necessary for the objective.",
        }

        return recommendations.get(
            stop_category.lower(),
            "Evaluate the risks and alternatives before deciding."
        )

    def request_override(
        self,
        stop_report: StopReport,
        proposed_action: str,
        override_scope: Optional[Dict[str, Any]] = None,
    ) -> OverrideDecision:
        """
        Request human override for a stop.

        Args:
            stop_report: The stop report.
            proposed_action: What would happen if override granted.
            override_scope: Scope/limits of the override.

        Returns:
            OverrideDecision from human.
        """
        if not stop_report.can_override:
            return OverrideDecision(
                override_id=f"override-denied-{uuid.uuid4().hex[:8]}",
                approved=False,
                responded_by="system",
                reason=(
                    f"Override not permitted for category: {stop_report.stop_category}. "
                    f"This is a hard security boundary."
                ),
            )

        request = OverrideRequest(
            override_id=f"override-{uuid.uuid4().hex[:8]}",
            session_id=self.session_id,
            stop_report=stop_report,
            proposed_action=proposed_action,
            risk_acknowledgment=self._generate_risk_acknowledgment(stop_report),
            override_scope=override_scope or {},
        )

        # Persist request
        if self.state_store:
            self.state_store.append_jsonl(
                "override_requests.jsonl",
                request.to_dict(),
            )

        # Request via callback
        if self.override_callback:
            decision = self.override_callback(request)
            self._record_decision(request, decision)
            return decision

        # No callback - deny
        decision = OverrideDecision(
            override_id=request.override_id,
            approved=False,
            responded_by="system",
            reason="No override callback configured - auto-denied for safety",
        )
        self._record_decision(request, decision)
        return decision

    def _generate_risk_acknowledgment(self, stop_report: StopReport) -> str:
        """Generate risk acknowledgment text."""
        return (
            f"I understand that overriding this stop ({stop_report.stop_category}) "
            f"may have the following impact: {stop_report.impact_if_continue}. "
            f"I accept responsibility for this decision."
        )

    def _record_decision(
        self,
        request: OverrideRequest,
        decision: OverrideDecision,
    ) -> None:
        """Record override decision."""
        if decision.approved:
            request.status = OverrideStatus.APPROVED

            # Calculate expiry
            expiry = None
            if decision.expiry_minutes:
                expiry_dt = datetime.utcnow() + timedelta(minutes=decision.expiry_minutes)
                expiry = expiry_dt.isoformat() + "Z"

            # Create override log
            override_log = OverrideLog(
                override_id=decision.override_id,
                session_id=self.session_id,
                category=request.stop_report.override_category or OverrideCategory.SAFETY_POLICY,
                original_stop_reason=request.stop_report.stop_reason,
                override_reason=decision.reason,
                approved_by=decision.responded_by,
                status=OverrideStatus.APPROVED,
                linked_phase=request.stop_report.phase,
                risk_acknowledgment=request.risk_acknowledgment,
                expiry=expiry,
                scope_of_override=decision.scope_modifications or request.override_scope,
            )

            self._active_overrides[decision.override_id] = override_log
            self._override_history.append(override_log)

            # Persist
            if self.state_store:
                self.state_store.append_jsonl(
                    "override_log.jsonl",
                    override_log.to_dict(),
                )
        else:
            request.status = OverrideStatus.REJECTED

    def is_override_active(self, override_id: str) -> bool:
        """Check if an override is still active."""
        override = self._active_overrides.get(override_id)
        if not override:
            return False
        return override.is_valid()

    def check_active_override(
        self,
        category: OverrideCategory,
        phase: str,
    ) -> Optional[OverrideLog]:
        """
        Check if there's an active override for a category/phase.

        Args:
            category: Override category.
            phase: Current phase.

        Returns:
            Active OverrideLog if found, None otherwise.
        """
        for override in self._active_overrides.values():
            if override.category == category and override.linked_phase == phase:
                if override.is_valid():
                    return override
                else:
                    # Expired - remove
                    del self._active_overrides[override.override_id]

        return None

    def revoke_override(
        self,
        override_id: str,
        revoked_by: str,
        reason: str,
    ) -> bool:
        """
        Revoke an active override.

        Args:
            override_id: ID of override to revoke.
            revoked_by: Who revoked it.
            reason: Reason for revocation.

        Returns:
            True if revoked, False if not found.
        """
        if override_id in self._active_overrides:
            override = self._active_overrides[override_id]
            override.status = OverrideStatus.EXPIRED

            del self._active_overrides[override_id]

            # Log revocation
            if self.state_store:
                self.state_store.append_jsonl(
                    "override_revocations.jsonl",
                    {
                        "override_id": override_id,
                        "revoked_by": revoked_by,
                        "reason": reason,
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    },
                )

            return True

        return False

    def get_active_overrides(self) -> List[OverrideLog]:
        """Get all active overrides."""
        # Clean expired
        expired = []
        for oid, override in self._active_overrides.items():
            if not override.is_valid():
                expired.append(oid)

        for oid in expired:
            del self._active_overrides[oid]

        return list(self._active_overrides.values())

    def get_override_history(self) -> List[OverrideLog]:
        """Get override history."""
        return self._override_history


def create_override_display(request: OverrideRequest) -> str:
    """
    Create human-readable display for override request.
    """
    report = request.stop_report
    lines = [
        "=" * 60,
        "OVERRIDE REQUESTED",
        "=" * 60,
        "",
        report.to_human_display(),
        "",
        "-" * 60,
        "",
        "### Proposed Action If Override Granted",
        request.proposed_action,
        "",
        "### Risk Acknowledgment Required",
        request.risk_acknowledgment,
        "",
    ]

    if request.override_scope:
        lines.extend([
            "### Override Scope/Limits",
        ])
        for key, value in request.override_scope.items():
            lines.append(f"- {key}: {value}")
        lines.append("")

    lines.extend([
        "-" * 60,
        "Options:",
        "  [O] Override and continue (requires acknowledgment)",
        "  [C] Cancel and stop",
        "  [A] Choose an alternative",
        "-" * 60,
    ])

    return "\n".join(lines)


def check_override_allowed(stop_category: str) -> tuple[bool, str]:
    """
    Check if override is allowed for a stop category.

    Returns:
        Tuple of (allowed, reason).
    """
    if stop_category.lower() in NON_OVERRIDABLE_CATEGORIES:
        return False, f"Category '{stop_category}' cannot be overridden for security reasons."

    return True, "Override is permitted for this category."
