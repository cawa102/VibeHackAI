"""
Patch Audit Log for PentestAgent.

Records all patch application attempts for audit and debugging.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import json

from .patch import Patch
from .applier import ApplyResult

if TYPE_CHECKING:
    from ..storage.state_store import StateStore


class AuditAction(str, Enum):
    """Types of audit actions."""
    APPLIED = "applied"
    REJECTED = "rejected"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class AuditEntry:
    """A single audit log entry."""

    timestamp: datetime
    patch_id: str
    session_id: str
    agent_id: str
    action: AuditAction
    base_version: int
    new_version: Optional[int]
    operations_count: int
    operations_applied: int
    success: bool
    error: Optional[str]
    validation_errors: List[str]
    affected_targets: List[str]
    operation_types: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat() + "Z",
            "patch_id": self.patch_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "action": self.action.value,
            "base_version": self.base_version,
            "new_version": self.new_version,
            "operations_count": self.operations_count,
            "operations_applied": self.operations_applied,
            "success": self.success,
            "error": self.error,
            "validation_errors": self.validation_errors,
            "affected_targets": self.affected_targets,
            "operation_types": self.operation_types,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        """Create from dictionary."""
        timestamp = data["timestamp"]
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.rstrip("Z"))

        return cls(
            timestamp=timestamp,
            patch_id=data["patch_id"],
            session_id=data["session_id"],
            agent_id=data["agent_id"],
            action=AuditAction(data["action"]),
            base_version=data["base_version"],
            new_version=data.get("new_version"),
            operations_count=data["operations_count"],
            operations_applied=data["operations_applied"],
            success=data["success"],
            error=data.get("error"),
            validation_errors=data.get("validation_errors", []),
            affected_targets=data.get("affected_targets", []),
            operation_types=data.get("operation_types", []),
        )


class PatchAuditLog:
    """
    Audit log for patch operations.

    Records all patch application attempts to a JSONL file.
    """

    AUDIT_FILE = "patch_audit.jsonl"

    def __init__(self, state_store: "StateStore"):
        """
        Initialize audit log.

        Args:
            state_store: State store to use for storage.
        """
        self.state_store = state_store

    def record(self, patch: Patch, result: ApplyResult) -> AuditEntry:
        """
        Record a patch application attempt.

        Args:
            patch: The patch that was applied or attempted.
            result: The result of the application attempt.

        Returns:
            The created audit entry.
        """
        # Determine action
        if result.success:
            action = AuditAction.APPLIED
        elif result.rolled_back:
            action = AuditAction.ROLLED_BACK
        elif result.validation_errors:
            action = AuditAction.REJECTED
        else:
            action = AuditAction.FAILED

        # Extract operation types
        op_types = [
            op.op if isinstance(op.op, str) else op.op.value
            for op in patch.operations
        ]

        entry = AuditEntry(
            timestamp=result.applied_at,
            patch_id=patch.patch_id,
            session_id=patch.session_id,
            agent_id=patch.agent_id,
            action=action,
            base_version=patch.base_state_version,
            new_version=result.new_state_version,
            operations_count=patch.operation_count(),
            operations_applied=result.operations_applied,
            success=result.success,
            error=result.error,
            validation_errors=result.validation_errors,
            affected_targets=patch.get_affected_targets(),
            operation_types=op_types,
        )

        # Append to audit log
        self.state_store.append_jsonl(self.AUDIT_FILE, entry.to_dict())

        return entry

    def record_rejection(
        self,
        patch: Patch,
        reason: str,
        validation_errors: Optional[List[str]] = None,
    ) -> AuditEntry:
        """
        Record a patch rejection (validation failure).

        Args:
            patch: The patch that was rejected.
            reason: Reason for rejection.
            validation_errors: List of validation error messages.

        Returns:
            The created audit entry.
        """
        op_types = [
            op.op if isinstance(op.op, str) else op.op.value
            for op in patch.operations
        ]

        entry = AuditEntry(
            timestamp=datetime.utcnow(),
            patch_id=patch.patch_id,
            session_id=patch.session_id,
            agent_id=patch.agent_id,
            action=AuditAction.REJECTED,
            base_version=patch.base_state_version,
            new_version=None,
            operations_count=patch.operation_count(),
            operations_applied=0,
            success=False,
            error=reason,
            validation_errors=validation_errors or [],
            affected_targets=patch.get_affected_targets(),
            operation_types=op_types,
        )

        self.state_store.append_jsonl(self.AUDIT_FILE, entry.to_dict())

        return entry

    def get_entries(
        self,
        limit: Optional[int] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        action: Optional[AuditAction] = None,
        success_only: bool = False,
    ) -> List[AuditEntry]:
        """
        Get audit log entries with optional filtering.

        Args:
            limit: Maximum number of entries to return.
            session_id: Filter by session ID.
            agent_id: Filter by agent ID.
            action: Filter by action type.
            success_only: Only return successful entries.

        Returns:
            List of matching audit entries, newest first.
        """
        records = self.state_store.read_jsonl(self.AUDIT_FILE)

        entries = []
        for record in reversed(records):  # Newest first
            entry = AuditEntry.from_dict(record)

            # Apply filters
            if session_id and entry.session_id != session_id:
                continue
            if agent_id and entry.agent_id != agent_id:
                continue
            if action and entry.action != action:
                continue
            if success_only and not entry.success:
                continue

            entries.append(entry)

            if limit and len(entries) >= limit:
                break

        return entries

    def get_entries_for_patch(self, patch_id: str) -> List[AuditEntry]:
        """
        Get all audit entries for a specific patch.

        Args:
            patch_id: The patch ID to look up.

        Returns:
            List of audit entries for this patch.
        """
        records = self.state_store.read_jsonl(self.AUDIT_FILE)

        entries = []
        for record in records:
            if record.get("patch_id") == patch_id:
                entries.append(AuditEntry.from_dict(record))

        return entries

    def get_recent_failures(self, limit: int = 10) -> List[AuditEntry]:
        """
        Get recent failed patch applications.

        Args:
            limit: Maximum number of entries to return.

        Returns:
            List of recent failed entries.
        """
        return self.get_entries(limit=limit, success_only=False)

    def get_agent_activity(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Get activity summary for an agent.

        Args:
            agent_id: The agent ID.
            limit: Maximum number of entries to consider.

        Returns:
            Dictionary with activity statistics.
        """
        entries = self.get_entries(limit=limit, agent_id=agent_id)

        total = len(entries)
        successful = sum(1 for e in entries if e.success)
        failed = total - successful

        # Count by action type
        action_counts = {}
        for entry in entries:
            action = entry.action.value
            action_counts[action] = action_counts.get(action, 0) + 1

        # Count by operation type
        op_counts = {}
        for entry in entries:
            for op_type in entry.operation_types:
                op_counts[op_type] = op_counts.get(op_type, 0) + 1

        return {
            "agent_id": agent_id,
            "total_patches": total,
            "successful": successful,
            "failed": failed,
            "success_rate": successful / total if total > 0 else 0,
            "action_counts": action_counts,
            "operation_counts": op_counts,
            "recent_errors": [e.error for e in entries if e.error][:5],
        }

    def count_entries(self) -> int:
        """Count total audit log entries."""
        return self.state_store.count_jsonl(self.AUDIT_FILE)

    def clear(self) -> None:
        """
        Clear the audit log (use with caution).

        This is mainly for testing purposes.
        """
        file_path = self.state_store.state_dir / self.AUDIT_FILE
        if file_path.exists():
            file_path.write_text("")
