"""
Router for Orchestrator - Phase management and routing logic.

Manages the phase progression: Recon → Enumeration → Planner → Exploitation
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..storage.state_store import StateStore


class Phase(str, Enum):
    """Phases of penetration testing workflow."""
    INIT = "init"
    RECON = "recon"
    ENUMERATION = "enumeration"
    PLANNER = "planner"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    STOPPED = "stopped"


class TransitionReason(str, Enum):
    """Reasons for phase transition."""
    NORMAL = "normal"              # Normal progression
    ROLLBACK = "rollback"          # Rolled back due to insufficient info
    SKIP = "skip"                  # Skipped due to sufficient info
    ERROR = "error"                # Transition due to error
    USER_REQUEST = "user_request"  # User requested transition
    STOP = "stop"                  # Stopped execution


@dataclass
class PhaseTransition:
    """Record of a phase transition."""
    from_phase: Phase
    to_phase: Phase
    reason: TransitionReason
    timestamp: datetime = dataclass_field(default_factory=datetime.utcnow)
    details: Optional[str] = None
    triggered_by: str = "orchestrator"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "from_phase": self.from_phase.value,
            "to_phase": self.to_phase.value,
            "reason": self.reason.value,
            "timestamp": self.timestamp.isoformat() + "Z",
            "details": self.details,
            "triggered_by": self.triggered_by,
        }


# Phase progression order
PHASE_ORDER = [
    Phase.INIT,
    Phase.RECON,
    Phase.ENUMERATION,
    Phase.PLANNER,
    Phase.EXPLOITATION,
    Phase.REPORTING,
    Phase.COMPLETED,
]

# Agent types for each phase
PHASE_AGENTS = {
    Phase.RECON: "recon_agent",
    Phase.ENUMERATION: "enumeration_agent",
    Phase.PLANNER: "planner_agent",
    Phase.EXPLOITATION: "exploitation_agent",
    Phase.REPORTING: "reporting_agent",
}


class Router:
    """
    Routes workflow between phases and agents.

    Manages phase transitions, rollbacks, and skip logic.
    """

    def __init__(self, state_store: Optional["StateStore"] = None):
        """
        Initialize router.

        Args:
            state_store: Optional state store for persistence.
        """
        self.state_store = state_store
        self._current_phase = Phase.INIT
        self._transitions: List[PhaseTransition] = []
        self._phase_results: Dict[Phase, Dict[str, Any]] = {}

    @property
    def current_phase(self) -> Phase:
        """Get current phase."""
        return self._current_phase

    @property
    def transitions(self) -> List[PhaseTransition]:
        """Get transition history."""
        return self._transitions.copy()

    def get_current_agent(self) -> Optional[str]:
        """Get agent type for current phase."""
        return PHASE_AGENTS.get(self._current_phase)

    def get_next_phase(self) -> Optional[Phase]:
        """
        Get the next phase in normal progression.

        Returns:
            Next phase or None if at end.
        """
        try:
            current_idx = PHASE_ORDER.index(self._current_phase)
            if current_idx < len(PHASE_ORDER) - 1:
                return PHASE_ORDER[current_idx + 1]
        except ValueError:
            pass
        return None

    def can_advance(self, phase_result: Optional[Dict[str, Any]] = None) -> bool:
        """
        Check if we can advance to next phase.

        Args:
            phase_result: Result from current phase agent.

        Returns:
            True if advancement is allowed.
        """
        if self._current_phase in (Phase.COMPLETED, Phase.STOPPED):
            return False

        if self._current_phase == Phase.INIT:
            return True

        if phase_result is None:
            return False

        # Check for blocking errors
        if phase_result.get("has_blocking_error"):
            return False

        # Check phase-specific requirements
        return self._check_phase_requirements(phase_result)

    def _check_phase_requirements(self, phase_result: Dict[str, Any]) -> bool:
        """Check phase-specific advancement requirements."""
        phase = self._current_phase

        if phase == Phase.RECON:
            # Need at least some target info
            return phase_result.get("targets_found", 0) > 0

        elif phase == Phase.ENUMERATION:
            # Need some enumeration data
            return (
                phase_result.get("services_found", 0) > 0 or
                phase_result.get("endpoints_found", 0) > 0
            )

        elif phase == Phase.PLANNER:
            # Need at least one plan or explicit "no candidates"
            return (
                phase_result.get("plans_created", 0) > 0 or
                phase_result.get("no_candidates", False)
            )

        elif phase == Phase.EXPLOITATION:
            # Always can advance after exploitation (to reporting)
            return True

        return True

    def should_rollback(self, phase_result: Dict[str, Any]) -> Optional[Phase]:
        """
        Determine if rollback is needed and to which phase.

        Args:
            phase_result: Result from current phase.

        Returns:
            Phase to rollback to, or None if no rollback needed.
        """
        rollback_reason = phase_result.get("rollback_reason")
        if not rollback_reason:
            return None

        phase = self._current_phase

        # Version not confirmed -> Recon
        if rollback_reason == "version_unconfirmed":
            return Phase.RECON

        # Insufficient reproduction steps -> Enumeration
        if rollback_reason == "insufficient_repro":
            return Phase.ENUMERATION

        # Exploit failed due to prerequisite mismatch
        if rollback_reason == "prerequisite_mismatch":
            # Decide based on what's missing
            if phase_result.get("missing_info_type") == "service_version":
                return Phase.ENUMERATION
            return Phase.PLANNER

        return None

    def should_skip(self, phase_result: Dict[str, Any]) -> bool:
        """
        Determine if current phase can be skipped.

        Args:
            phase_result: Result indicating skip eligibility.

        Returns:
            True if skip is recommended.
        """
        # Check if we have sufficient info from previous phases
        if phase_result.get("sufficient_info"):
            return True

        phase = self._current_phase

        if phase == Phase.RECON:
            # Can skip if Shodan/OSINT provided enough info
            return phase_result.get("external_intel_sufficient", False)

        if phase == Phase.ENUMERATION:
            # Can skip if recon was thorough
            return phase_result.get("recon_comprehensive", False)

        return False

    def advance(
        self,
        phase_result: Optional[Dict[str, Any]] = None,
        reason: TransitionReason = TransitionReason.NORMAL,
        details: Optional[str] = None,
        triggered_by: str = "orchestrator",
    ) -> PhaseTransition:
        """
        Advance to next phase.

        Args:
            phase_result: Result from current phase.
            reason: Reason for transition.
            details: Additional details.
            triggered_by: Who triggered the transition.

        Returns:
            The phase transition record.

        Raises:
            ValueError: If cannot advance.
        """
        next_phase = self.get_next_phase()
        if next_phase is None:
            raise ValueError(f"Cannot advance from {self._current_phase}")

        return self._transition_to(
            next_phase, reason, details, triggered_by, phase_result
        )

    def rollback_to(
        self,
        target_phase: Phase,
        details: Optional[str] = None,
        triggered_by: str = "orchestrator",
    ) -> PhaseTransition:
        """
        Rollback to a previous phase.

        Args:
            target_phase: Phase to rollback to.
            details: Reason for rollback.
            triggered_by: Who triggered the rollback.

        Returns:
            The phase transition record.

        Raises:
            ValueError: If target phase is not before current.
        """
        try:
            target_idx = PHASE_ORDER.index(target_phase)
            current_idx = PHASE_ORDER.index(self._current_phase)
            if target_idx >= current_idx:
                raise ValueError(
                    f"Cannot rollback from {self._current_phase} to {target_phase}"
                )
        except ValueError as e:
            raise ValueError(f"Invalid phase: {e}")

        return self._transition_to(
            target_phase, TransitionReason.ROLLBACK, details, triggered_by
        )

    def skip_to(
        self,
        target_phase: Phase,
        details: Optional[str] = None,
        triggered_by: str = "orchestrator",
    ) -> PhaseTransition:
        """
        Skip to a later phase.

        Args:
            target_phase: Phase to skip to.
            details: Reason for skip.
            triggered_by: Who triggered the skip.

        Returns:
            The phase transition record.

        Raises:
            ValueError: If target phase is not after current.
        """
        try:
            target_idx = PHASE_ORDER.index(target_phase)
            current_idx = PHASE_ORDER.index(self._current_phase)
            if target_idx <= current_idx:
                raise ValueError(
                    f"Cannot skip from {self._current_phase} to {target_phase}"
                )
        except ValueError as e:
            raise ValueError(f"Invalid phase: {e}")

        return self._transition_to(
            target_phase, TransitionReason.SKIP, details, triggered_by
        )

    def stop(
        self,
        reason: str,
        triggered_by: str = "orchestrator",
    ) -> PhaseTransition:
        """
        Stop execution.

        Args:
            reason: Reason for stopping.
            triggered_by: Who triggered the stop.

        Returns:
            The phase transition record.
        """
        return self._transition_to(
            Phase.STOPPED, TransitionReason.STOP, reason, triggered_by
        )

    def _transition_to(
        self,
        target_phase: Phase,
        reason: TransitionReason,
        details: Optional[str],
        triggered_by: str,
        phase_result: Optional[Dict[str, Any]] = None,
    ) -> PhaseTransition:
        """Internal transition method."""
        transition = PhaseTransition(
            from_phase=self._current_phase,
            to_phase=target_phase,
            reason=reason,
            details=details,
            triggered_by=triggered_by,
        )

        # Store result for current phase
        if phase_result:
            self._phase_results[self._current_phase] = phase_result

        self._transitions.append(transition)
        self._current_phase = target_phase

        # Persist if state store available
        if self.state_store:
            self._persist_transition(transition)

        return transition

    def _persist_transition(self, transition: PhaseTransition) -> None:
        """Persist transition to state store."""
        if self.state_store:
            self.state_store.append_jsonl(
                "phase_transitions.jsonl",
                transition.to_dict()
            )

    def get_phase_result(self, phase: Phase) -> Optional[Dict[str, Any]]:
        """Get stored result for a phase."""
        return self._phase_results.get(phase)

    def get_state(self) -> Dict[str, Any]:
        """Get current router state."""
        return {
            "current_phase": self._current_phase.value,
            "transitions_count": len(self._transitions),
            "phase_results": {
                p.value: r for p, r in self._phase_results.items()
            },
        }

    def load_state(self, state: Dict[str, Any]) -> None:
        """Load router state from dictionary."""
        self._current_phase = Phase(state["current_phase"])
        self._phase_results = {
            Phase(p): r for p, r in state.get("phase_results", {}).items()
        }
