"""
Stop Monitor for Orchestrator.

Monitors for stop conditions and triggers emergency stops.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..storage.state_store import StateStore
    from ..schemas.execution_result import ErrorClass


class StopReason(str, Enum):
    """Reasons for stopping execution."""
    CONSECUTIVE_ERRORS = "consecutive_errors"
    SCOPE_VIOLATION = "scope_violation"
    DOS_DETECTED = "dos_detected"
    DESTRUCTIVE_BEHAVIOR = "destructive_behavior"
    USER_REQUESTED = "user_requested"
    TIMEOUT = "timeout"
    UNKNOWN_ERROR = "unknown_error"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


@dataclass
class StopCondition:
    """A detected stop condition."""
    reason: StopReason
    severity: str  # warning, critical, emergency
    message: str
    details: Dict[str, Any] = dataclass_field(default_factory=dict)
    detected_at: datetime = dataclass_field(default_factory=datetime.utcnow)
    auto_stop: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "reason": self.reason.value,
            "severity": self.severity,
            "message": self.message,
            "details": self.details,
            "detected_at": self.detected_at.isoformat() + "Z",
            "auto_stop": self.auto_stop,
        }


class StopMonitor:
    """
    Monitors for stop conditions.

    Tracks errors, scope violations, and anomalous behavior.
    """

    # Default thresholds
    DEFAULT_CONSECUTIVE_ERROR_THRESHOLD = 2
    DEFAULT_TOTAL_ERROR_THRESHOLD = 10
    DEFAULT_RATE_LIMIT_THRESHOLD = 100  # requests per minute

    def __init__(
        self,
        state_store: Optional["StateStore"] = None,
        consecutive_error_threshold: int = DEFAULT_CONSECUTIVE_ERROR_THRESHOLD,
        total_error_threshold: int = DEFAULT_TOTAL_ERROR_THRESHOLD,
        rate_limit_threshold: int = DEFAULT_RATE_LIMIT_THRESHOLD,
    ):
        """
        Initialize stop monitor.

        Args:
            state_store: State store for persistence.
            consecutive_error_threshold: Max consecutive errors before stop.
            total_error_threshold: Max total errors before stop.
            rate_limit_threshold: Max requests per minute.
        """
        self.state_store = state_store
        self.consecutive_error_threshold = consecutive_error_threshold
        self.total_error_threshold = total_error_threshold
        self.rate_limit_threshold = rate_limit_threshold

        # Error tracking
        self._error_counts: Dict[str, int] = {}  # error_class -> count
        self._consecutive_errors: Dict[str, int] = {}  # error_class -> consecutive count
        self._last_error_class: Optional[str] = None
        self._total_errors = 0

        # Request tracking
        self._request_timestamps: List[datetime] = []

        # Stop conditions
        self._stop_conditions: List[StopCondition] = []
        self._should_stop = False
        self._stop_reason: Optional[StopReason] = None

    @property
    def should_stop(self) -> bool:
        """Check if execution should stop."""
        return self._should_stop

    @property
    def stop_reason(self) -> Optional[StopReason]:
        """Get the reason for stopping."""
        return self._stop_reason

    @property
    def stop_conditions(self) -> List[StopCondition]:
        """Get all detected stop conditions."""
        return self._stop_conditions.copy()

    def record_error(
        self,
        error_class: str,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Optional[StopCondition]:
        """
        Record an error occurrence.

        Args:
            error_class: Class/type of error.
            message: Error message.
            details: Additional details.

        Returns:
            StopCondition if stop threshold reached, None otherwise.
        """
        self._total_errors += 1
        self._error_counts[error_class] = self._error_counts.get(error_class, 0) + 1

        # Track consecutive errors
        if error_class == self._last_error_class:
            self._consecutive_errors[error_class] = (
                self._consecutive_errors.get(error_class, 0) + 1
            )
        else:
            self._consecutive_errors[error_class] = 1
            self._last_error_class = error_class

        # Check consecutive error threshold
        if self._consecutive_errors[error_class] >= self.consecutive_error_threshold:
            condition = StopCondition(
                reason=StopReason.CONSECUTIVE_ERRORS,
                severity="critical",
                message=f"Consecutive errors threshold reached for {error_class}",
                details={
                    "error_class": error_class,
                    "count": self._consecutive_errors[error_class],
                    "threshold": self.consecutive_error_threshold,
                    "last_message": message,
                },
            )
            self._add_stop_condition(condition)
            return condition

        # Check total error threshold
        if self._total_errors >= self.total_error_threshold:
            condition = StopCondition(
                reason=StopReason.UNKNOWN_ERROR,
                severity="warning",
                message=f"Total error threshold reached",
                details={
                    "total_errors": self._total_errors,
                    "threshold": self.total_error_threshold,
                    "error_counts": self._error_counts.copy(),
                },
                auto_stop=False,  # Warning only
            )
            self._add_stop_condition(condition)
            return condition

        return None

    def record_success(self) -> None:
        """Record a successful operation (resets consecutive error counts)."""
        self._last_error_class = None
        # Don't reset consecutive counts entirely - just the streak

    def check_scope_violation(
        self,
        target: str,
        scope_targets: List[str],
    ) -> Optional[StopCondition]:
        """
        Check for scope violation.

        Args:
            target: Target being accessed.
            scope_targets: List of allowed targets.

        Returns:
            StopCondition if violation detected.
        """
        if target not in scope_targets:
            # Check if it's a partial match (IP in CIDR, subdomain, etc.)
            is_in_scope = False
            for allowed in scope_targets:
                if self._is_target_in_scope(target, allowed):
                    is_in_scope = True
                    break

            if not is_in_scope:
                condition = StopCondition(
                    reason=StopReason.SCOPE_VIOLATION,
                    severity="emergency",
                    message=f"Target '{target}' is outside defined scope",
                    details={
                        "target": target,
                        "allowed_targets": scope_targets,
                    },
                )
                self._add_stop_condition(condition)
                return condition

        return None

    def _is_target_in_scope(self, target: str, allowed: str) -> bool:
        """Check if target matches an allowed scope entry."""
        # Exact match
        if target == allowed:
            return True

        # Check CIDR containment
        if "/" in allowed:
            try:
                import ipaddress
                network = ipaddress.ip_network(allowed, strict=False)
                return ipaddress.ip_address(target) in network
            except (ValueError, ImportError):
                pass

        # Check subdomain
        if target.endswith("." + allowed):
            return True

        return False

    def check_dos_indicators(
        self,
        requests_count: int,
        time_window_seconds: float,
    ) -> Optional[StopCondition]:
        """
        Check for DoS-like behavior.

        Args:
            requests_count: Number of requests in window.
            time_window_seconds: Time window in seconds.

        Returns:
            StopCondition if DoS indicators detected.
        """
        # Calculate rate per minute
        if time_window_seconds <= 0:
            return None

        rate_per_minute = (requests_count / time_window_seconds) * 60

        if rate_per_minute > self.rate_limit_threshold:
            condition = StopCondition(
                reason=StopReason.DOS_DETECTED,
                severity="critical",
                message=f"Potential DoS behavior detected",
                details={
                    "requests_count": requests_count,
                    "time_window_seconds": time_window_seconds,
                    "rate_per_minute": rate_per_minute,
                    "threshold": self.rate_limit_threshold,
                },
            )
            self._add_stop_condition(condition)
            return condition

        return None

    def check_destructive_behavior(
        self,
        operation: str,
        target: str,
    ) -> Optional[StopCondition]:
        """
        Check for destructive behavior patterns.

        Args:
            operation: Operation being performed.
            target: Target of operation.

        Returns:
            StopCondition if destructive behavior detected.
        """
        destructive_patterns = [
            "rm -rf",
            "format",
            "delete all",
            "drop database",
            "truncate",
            "wipe",
            ":(){:|:&};:",  # Fork bomb
        ]

        operation_lower = operation.lower()
        for pattern in destructive_patterns:
            if pattern in operation_lower:
                condition = StopCondition(
                    reason=StopReason.DESTRUCTIVE_BEHAVIOR,
                    severity="emergency",
                    message=f"Destructive behavior pattern detected: {pattern}",
                    details={
                        "operation": operation,
                        "target": target,
                        "pattern": pattern,
                    },
                )
                self._add_stop_condition(condition)
                return condition

        return None

    def request_stop(
        self,
        reason: str,
        requested_by: str,
    ) -> StopCondition:
        """
        Request manual stop.

        Args:
            reason: Reason for stop request.
            requested_by: Who requested the stop.

        Returns:
            StopCondition.
        """
        condition = StopCondition(
            reason=StopReason.USER_REQUESTED,
            severity="critical",
            message=f"Stop requested by {requested_by}: {reason}",
            details={
                "reason": reason,
                "requested_by": requested_by,
            },
        )
        self._add_stop_condition(condition)
        return condition

    def _add_stop_condition(self, condition: StopCondition) -> None:
        """Add a stop condition."""
        self._stop_conditions.append(condition)

        if condition.auto_stop:
            self._should_stop = True
            self._stop_reason = condition.reason

        # Persist if state store available
        if self.state_store:
            self.state_store.append_jsonl(
                "stop_conditions.jsonl",
                condition.to_dict()
            )

    def clear_stop(self) -> None:
        """Clear stop flag (for resuming after review)."""
        self._should_stop = False
        self._stop_reason = None

    def reset_error_counts(self) -> None:
        """Reset error tracking."""
        self._error_counts.clear()
        self._consecutive_errors.clear()
        self._last_error_class = None
        self._total_errors = 0

    def get_status(self) -> Dict[str, Any]:
        """Get current monitor status."""
        return {
            "should_stop": self._should_stop,
            "stop_reason": self._stop_reason.value if self._stop_reason else None,
            "total_errors": self._total_errors,
            "error_counts": self._error_counts.copy(),
            "consecutive_errors": self._consecutive_errors.copy(),
            "stop_conditions_count": len(self._stop_conditions),
        }

    def create_snapshot(self) -> Dict[str, Any]:
        """Create state snapshot for emergency stop."""
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "should_stop": self._should_stop,
            "stop_reason": self._stop_reason.value if self._stop_reason else None,
            "total_errors": self._total_errors,
            "error_counts": self._error_counts.copy(),
            "consecutive_errors": self._consecutive_errors.copy(),
            "stop_conditions": [c.to_dict() for c in self._stop_conditions],
        }

    def save_emergency_snapshot(self) -> Optional[str]:
        """Save emergency snapshot to state store."""
        if not self.state_store:
            return None

        snapshot = self.create_snapshot()
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"emergency_snapshot_{timestamp}.json"
        self.state_store.write_json(filename, snapshot)
        return filename
