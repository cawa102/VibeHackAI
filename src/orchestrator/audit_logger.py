"""
Audit Logger for Orchestrator.

Records all orchestrator operations for audit trail.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..storage.state_store import StateStore


class AuditEventType(str, Enum):
    """Types of audit events."""
    # Session events
    SESSION_START = "session_start"
    SESSION_END = "session_end"

    # Phase events
    PHASE_TRANSITION = "phase_transition"
    PHASE_ROLLBACK = "phase_rollback"
    PHASE_SKIP = "phase_skip"

    # Agent events
    AGENT_INVOKED = "agent_invoked"
    AGENT_COMPLETED = "agent_completed"
    AGENT_FAILED = "agent_failed"

    # Approval events
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_TIMEOUT = "approval_timeout"

    # Patch events
    PATCH_RECEIVED = "patch_received"
    PATCH_VALIDATED = "patch_validated"
    PATCH_APPLIED = "patch_applied"
    PATCH_REJECTED = "patch_rejected"

    # Stop events
    STOP_CONDITION = "stop_condition"
    EMERGENCY_STOP = "emergency_stop"
    USER_STOP = "user_stop"

    # Other
    SCOPE_LOADED = "scope_loaded"
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class AuditEvent:
    """An audit log event."""
    event_type: AuditEventType
    session_id: str
    timestamp: datetime = dataclass_field(default_factory=datetime.utcnow)
    actor: str = "orchestrator"
    message: str = ""
    details: Dict[str, Any] = dataclass_field(default_factory=dict)
    phase: Optional[str] = None
    agent: Optional[str] = None
    patch_id: Optional[str] = None
    approval_id: Optional[str] = None
    state_version: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_type": self.event_type.value,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() + "Z",
            "actor": self.actor,
            "message": self.message,
            "details": self.details,
            "phase": self.phase,
            "agent": self.agent,
            "patch_id": self.patch_id,
            "approval_id": self.approval_id,
            "state_version": self.state_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """Create from dictionary."""
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.rstrip("Z"))

        return cls(
            event_type=AuditEventType(data["event_type"]),
            session_id=data["session_id"],
            timestamp=timestamp or datetime.utcnow(),
            actor=data.get("actor", "orchestrator"),
            message=data.get("message", ""),
            details=data.get("details", {}),
            phase=data.get("phase"),
            agent=data.get("agent"),
            patch_id=data.get("patch_id"),
            approval_id=data.get("approval_id"),
            state_version=data.get("state_version"),
        )


class OrchestratorAuditLogger:
    """
    Audit logger for orchestrator operations.

    Records all events to a JSONL file for audit trail.
    """

    AUDIT_FILE = "orchestrator_audit.jsonl"

    def __init__(
        self,
        state_store: "StateStore",
        session_id: str,
    ):
        """
        Initialize audit logger.

        Args:
            state_store: State store for persistence.
            session_id: Current session ID.
        """
        self.state_store = state_store
        self.session_id = session_id

    def log(
        self,
        event_type: AuditEventType,
        message: str = "",
        actor: str = "orchestrator",
        details: Optional[Dict[str, Any]] = None,
        phase: Optional[str] = None,
        agent: Optional[str] = None,
        patch_id: Optional[str] = None,
        approval_id: Optional[str] = None,
    ) -> AuditEvent:
        """
        Log an audit event.

        Args:
            event_type: Type of event.
            message: Human-readable message.
            actor: Who/what triggered the event.
            details: Additional details.
            phase: Current phase.
            agent: Related agent.
            patch_id: Related patch ID.
            approval_id: Related approval ID.

        Returns:
            The created AuditEvent.
        """
        state_version = self.state_store.get_version()

        event = AuditEvent(
            event_type=event_type,
            session_id=self.session_id,
            actor=actor,
            message=message,
            details=details or {},
            phase=phase,
            agent=agent,
            patch_id=patch_id,
            approval_id=approval_id,
            state_version=state_version,
        )

        self.state_store.append_jsonl(self.AUDIT_FILE, event.to_dict())
        return event

    # Convenience methods for common events

    def log_session_start(
        self,
        scope_tag: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log session start."""
        return self.log(
            AuditEventType.SESSION_START,
            f"Session started for scope: {scope_tag}",
            details={**(details or {}), "scope_tag": scope_tag},
        )

    def log_session_end(
        self,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log session end."""
        return self.log(
            AuditEventType.SESSION_END,
            f"Session ended: {reason}",
            details={**(details or {}), "reason": reason},
        )

    def log_phase_transition(
        self,
        from_phase: str,
        to_phase: str,
        reason: str,
        triggered_by: str = "orchestrator",
    ) -> AuditEvent:
        """Log phase transition."""
        return self.log(
            AuditEventType.PHASE_TRANSITION,
            f"Phase transition: {from_phase} -> {to_phase}",
            actor=triggered_by,
            details={
                "from_phase": from_phase,
                "to_phase": to_phase,
                "reason": reason,
            },
            phase=to_phase,
        )

    def log_agent_invoked(
        self,
        agent: str,
        phase: str,
        context_size: Optional[int] = None,
    ) -> AuditEvent:
        """Log agent invocation."""
        return self.log(
            AuditEventType.AGENT_INVOKED,
            f"Agent invoked: {agent}",
            agent=agent,
            phase=phase,
            details={"context_size": context_size} if context_size else {},
        )

    def log_agent_completed(
        self,
        agent: str,
        phase: str,
        success: bool,
        duration_ms: Optional[int] = None,
    ) -> AuditEvent:
        """Log agent completion."""
        return self.log(
            AuditEventType.AGENT_COMPLETED,
            f"Agent completed: {agent} (success={success})",
            agent=agent,
            phase=phase,
            details={
                "success": success,
                "duration_ms": duration_ms,
            },
        )

    def log_agent_failed(
        self,
        agent: str,
        phase: str,
        error: str,
    ) -> AuditEvent:
        """Log agent failure."""
        return self.log(
            AuditEventType.AGENT_FAILED,
            f"Agent failed: {agent} - {error}",
            agent=agent,
            phase=phase,
            details={"error": error},
        )

    def log_approval_requested(
        self,
        approval_id: str,
        operation: str,
        target: str,
    ) -> AuditEvent:
        """Log approval request."""
        return self.log(
            AuditEventType.APPROVAL_REQUESTED,
            f"Approval requested for {operation} on {target}",
            approval_id=approval_id,
            details={
                "operation": operation,
                "target": target,
            },
        )

    def log_approval_granted(
        self,
        approval_id: str,
        approved_by: str,
    ) -> AuditEvent:
        """Log approval granted."""
        return self.log(
            AuditEventType.APPROVAL_GRANTED,
            f"Approval granted by {approved_by}",
            actor=approved_by,
            approval_id=approval_id,
        )

    def log_approval_denied(
        self,
        approval_id: str,
        denied_by: str,
        reason: str,
    ) -> AuditEvent:
        """Log approval denied."""
        return self.log(
            AuditEventType.APPROVAL_DENIED,
            f"Approval denied by {denied_by}: {reason}",
            actor=denied_by,
            approval_id=approval_id,
            details={"reason": reason},
        )

    def log_patch_received(
        self,
        patch_id: str,
        agent: str,
        operations_count: int,
    ) -> AuditEvent:
        """Log patch received."""
        return self.log(
            AuditEventType.PATCH_RECEIVED,
            f"Patch received from {agent} with {operations_count} operations",
            agent=agent,
            patch_id=patch_id,
            details={"operations_count": operations_count},
        )

    def log_patch_applied(
        self,
        patch_id: str,
        operations_applied: int,
        new_version: int,
    ) -> AuditEvent:
        """Log patch applied."""
        return self.log(
            AuditEventType.PATCH_APPLIED,
            f"Patch applied: {operations_applied} operations, new version {new_version}",
            patch_id=patch_id,
            details={
                "operations_applied": operations_applied,
                "new_version": new_version,
            },
        )

    def log_patch_rejected(
        self,
        patch_id: str,
        reason: str,
        errors: Optional[List[str]] = None,
    ) -> AuditEvent:
        """Log patch rejection."""
        return self.log(
            AuditEventType.PATCH_REJECTED,
            f"Patch rejected: {reason}",
            patch_id=patch_id,
            details={
                "reason": reason,
                "errors": errors or [],
            },
        )

    def log_stop_condition(
        self,
        reason: str,
        severity: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log stop condition."""
        return self.log(
            AuditEventType.STOP_CONDITION,
            f"Stop condition detected: {reason}",
            details={
                **(details or {}),
                "reason": reason,
                "severity": severity,
            },
        )

    def log_emergency_stop(
        self,
        reason: str,
        triggered_by: str,
    ) -> AuditEvent:
        """Log emergency stop."""
        return self.log(
            AuditEventType.EMERGENCY_STOP,
            f"Emergency stop: {reason}",
            actor=triggered_by,
            details={"reason": reason},
        )

    def log_error(
        self,
        error: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log error."""
        return self.log(
            AuditEventType.ERROR,
            f"Error: {error}",
            details={**(details or {}), "error": error},
        )

    def log_warning(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log warning."""
        return self.log(
            AuditEventType.WARNING,
            message,
            details=details,
        )

    def log_info(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Log info."""
        return self.log(
            AuditEventType.INFO,
            message,
            details=details,
        )

    # Query methods

    def get_events(
        self,
        event_type: Optional[AuditEventType] = None,
        limit: Optional[int] = None,
    ) -> List[AuditEvent]:
        """
        Get audit events.

        Args:
            event_type: Filter by event type.
            limit: Maximum number of events.

        Returns:
            List of audit events, newest first.
        """
        records = self.state_store.read_jsonl(self.AUDIT_FILE)

        events = []
        for record in reversed(records):
            # Filter by session
            if record.get("session_id") != self.session_id:
                continue

            # Filter by type
            if event_type and record.get("event_type") != event_type.value:
                continue

            events.append(AuditEvent.from_dict(record))

            if limit and len(events) >= limit:
                break

        return events

    def get_phase_history(self) -> List[AuditEvent]:
        """Get phase transition history."""
        transition_types = {
            AuditEventType.PHASE_TRANSITION,
            AuditEventType.PHASE_ROLLBACK,
            AuditEventType.PHASE_SKIP,
        }

        records = self.state_store.read_jsonl(self.AUDIT_FILE)
        events = []

        for record in records:
            if record.get("session_id") != self.session_id:
                continue

            event_type = record.get("event_type")
            if event_type in {t.value for t in transition_types}:
                events.append(AuditEvent.from_dict(record))

        return events

    def get_approval_history(self) -> List[AuditEvent]:
        """Get approval event history."""
        approval_types = {
            AuditEventType.APPROVAL_REQUESTED,
            AuditEventType.APPROVAL_GRANTED,
            AuditEventType.APPROVAL_DENIED,
            AuditEventType.APPROVAL_TIMEOUT,
        }

        records = self.state_store.read_jsonl(self.AUDIT_FILE)
        events = []

        for record in records:
            if record.get("session_id") != self.session_id:
                continue

            event_type = record.get("event_type")
            if event_type in {t.value for t in approval_types}:
                events.append(AuditEvent.from_dict(record))

        return events

    def count_events(self) -> int:
        """Count total events for this session."""
        records = self.state_store.read_jsonl(self.AUDIT_FILE)
        return sum(1 for r in records if r.get("session_id") == self.session_id)
