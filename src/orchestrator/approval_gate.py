"""
Approval Gate for Orchestrator.

Manages approval requirements for dangerous operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..storage.state_store import StateStore
    from ..patch.patch import Patch


class ApprovalStatus(str, Enum):
    """Status of approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


# Operations that always require approval
APPROVAL_REQUIRED_OPERATIONS = {
    # Metasploit execution
    "metasploit_execute",
    "msf_run",
    "exploit_execute",
    # Payload operations
    "payload_deliver",
    "shell_spawn",
    "reverse_shell",
    "meterpreter",
    # Persistence
    "persistence_install",
    "backdoor",
    # Brute force
    "brute_force",
    "password_spray",
    "credential_stuff",
    # Destructive
    "file_modify",
    "file_delete",
    "config_change",
    "privilege_escalation",
    # High frequency
    "rate_limit_bypass",
    "flood",
}

# Tools that require approval
APPROVAL_REQUIRED_TOOLS = {
    "metasploit",
    "msfconsole",
    "msfvenom",
    "hydra",
    "medusa",
    "john",
    "hashcat",
}


@dataclass
class ApprovalRequest:
    """Request for human approval."""
    request_id: str
    operation: str
    tool: Optional[str]
    target: str
    description: str
    risk_level: str
    patch_id: Optional[str] = None
    details: Dict[str, Any] = dataclass_field(default_factory=dict)
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = dataclass_field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    responded_at: Optional[datetime] = None
    responded_by: Optional[str] = None
    rejection_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "operation": self.operation,
            "tool": self.tool,
            "target": self.target,
            "description": self.description,
            "risk_level": self.risk_level,
            "patch_id": self.patch_id,
            "details": self.details,
            "status": self.status.value,
            "created_at": self.created_at.isoformat() + "Z",
            "expires_at": self.expires_at.isoformat() + "Z" if self.expires_at else None,
            "responded_at": self.responded_at.isoformat() + "Z" if self.responded_at else None,
            "responded_by": self.responded_by,
            "rejection_reason": self.rejection_reason,
        }

    def is_expired(self) -> bool:
        """Check if request has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at


@dataclass
class ApprovalResult:
    """Result of approval request."""
    request_id: str
    approved: bool
    responded_by: Optional[str] = None
    reason: Optional[str] = None
    timestamp: datetime = dataclass_field(default_factory=datetime.utcnow)


class ApprovalGate:
    """
    Gate for approving dangerous operations.

    Checks if operations require approval and manages the approval process.
    """

    DEFAULT_TIMEOUT_MINUTES = 5

    def __init__(
        self,
        state_store: Optional["StateStore"] = None,
        timeout_minutes: int = DEFAULT_TIMEOUT_MINUTES,
        approval_callback: Optional[Callable[[ApprovalRequest], ApprovalResult]] = None,
    ):
        """
        Initialize approval gate.

        Args:
            state_store: State store for persistence.
            timeout_minutes: Timeout for approval requests.
            approval_callback: Callback function to request approval.
        """
        self.state_store = state_store
        self.timeout_minutes = timeout_minutes
        self.approval_callback = approval_callback
        self._pending_requests: Dict[str, ApprovalRequest] = {}

    def requires_approval(
        self,
        operation: str,
        tool: Optional[str] = None,
        patch: Optional["Patch"] = None,
    ) -> bool:
        """
        Check if an operation requires approval.

        Args:
            operation: Operation name/type.
            tool: Tool being used.
            patch: Optional patch containing operations.

        Returns:
            True if approval is required.
        """
        # Check operation
        operation_lower = operation.lower()
        if operation_lower in APPROVAL_REQUIRED_OPERATIONS:
            return True

        # Check for keywords in operation
        dangerous_keywords = [
            "exploit", "payload", "shell", "meterpreter",
            "brute", "password", "credential", "persist",
            "backdoor", "privilege", "escalat"
        ]
        if any(kw in operation_lower for kw in dangerous_keywords):
            return True

        # Check tool
        if tool and tool.lower() in APPROVAL_REQUIRED_TOOLS:
            return True

        # Check patch operations
        if patch:
            for op in patch.operations:
                if op.requires_approval:
                    return True

        return False

    def create_request(
        self,
        operation: str,
        target: str,
        description: str,
        tool: Optional[str] = None,
        patch_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        risk_level: str = "high",
    ) -> ApprovalRequest:
        """
        Create an approval request.

        Args:
            operation: Operation requiring approval.
            target: Target of the operation.
            description: Human-readable description.
            tool: Tool being used.
            patch_id: Associated patch ID.
            details: Additional details.
            risk_level: Risk level (low, medium, high, critical).

        Returns:
            The created ApprovalRequest.
        """
        import uuid

        request_id = f"approval-{uuid.uuid4()}"
        expires_at = datetime.utcnow() + timedelta(minutes=self.timeout_minutes)

        request = ApprovalRequest(
            request_id=request_id,
            operation=operation,
            tool=tool,
            target=target,
            description=description,
            risk_level=risk_level,
            patch_id=patch_id,
            details=details or {},
            expires_at=expires_at,
        )

        self._pending_requests[request_id] = request

        # Persist if state store available
        if self.state_store:
            self.state_store.append_jsonl(
                "approval_requests.jsonl",
                request.to_dict()
            )

        return request

    def request_approval(
        self,
        request: ApprovalRequest,
    ) -> ApprovalResult:
        """
        Request approval (blocking).

        Args:
            request: The approval request.

        Returns:
            ApprovalResult with decision.
        """
        if self.approval_callback:
            result = self.approval_callback(request)
            self._record_response(request, result)
            return result

        # No callback - auto-reject for safety
        result = ApprovalResult(
            request_id=request.request_id,
            approved=False,
            reason="No approval callback configured - auto-rejected",
        )
        self._record_response(request, result)
        return result

    def approve(
        self,
        request_id: str,
        approved_by: str,
        reason: Optional[str] = None,
    ) -> ApprovalResult:
        """
        Approve a pending request.

        Args:
            request_id: ID of the request to approve.
            approved_by: Who approved the request.
            reason: Optional reason/notes.

        Returns:
            ApprovalResult.

        Raises:
            ValueError: If request not found or already processed.
        """
        request = self._pending_requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(f"Request already processed: {request.status}")

        if request.is_expired():
            request.status = ApprovalStatus.TIMEOUT
            raise ValueError("Request has expired")

        result = ApprovalResult(
            request_id=request_id,
            approved=True,
            responded_by=approved_by,
            reason=reason,
        )

        self._record_response(request, result)
        return result

    def reject(
        self,
        request_id: str,
        rejected_by: str,
        reason: str,
    ) -> ApprovalResult:
        """
        Reject a pending request.

        Args:
            request_id: ID of the request to reject.
            rejected_by: Who rejected the request.
            reason: Reason for rejection.

        Returns:
            ApprovalResult.

        Raises:
            ValueError: If request not found or already processed.
        """
        request = self._pending_requests.get(request_id)
        if not request:
            raise ValueError(f"Request not found: {request_id}")

        if request.status != ApprovalStatus.PENDING:
            raise ValueError(f"Request already processed: {request.status}")

        result = ApprovalResult(
            request_id=request_id,
            approved=False,
            responded_by=rejected_by,
            reason=reason,
        )

        self._record_response(request, result)
        return result

    def _record_response(
        self,
        request: ApprovalRequest,
        result: ApprovalResult,
    ) -> None:
        """Record approval response."""
        request.responded_at = result.timestamp
        request.responded_by = result.responded_by

        if result.approved:
            request.status = ApprovalStatus.APPROVED
        else:
            request.status = ApprovalStatus.REJECTED
            request.rejection_reason = result.reason

        # Remove from pending
        if request.request_id in self._pending_requests:
            del self._pending_requests[request.request_id]

        # Persist response
        if self.state_store:
            self.state_store.append_jsonl(
                "approval_responses.jsonl",
                {
                    "request_id": request.request_id,
                    "approved": result.approved,
                    "responded_by": result.responded_by,
                    "reason": result.reason,
                    "timestamp": result.timestamp.isoformat() + "Z",
                }
            )

    def get_pending_requests(self) -> List[ApprovalRequest]:
        """Get all pending requests."""
        # Check for expired
        now = datetime.utcnow()
        expired = []
        for req_id, req in self._pending_requests.items():
            if req.expires_at and now > req.expires_at:
                req.status = ApprovalStatus.TIMEOUT
                expired.append(req_id)

        for req_id in expired:
            del self._pending_requests[req_id]

        return list(self._pending_requests.values())

    def cancel_request(self, request_id: str) -> None:
        """Cancel a pending request."""
        if request_id in self._pending_requests:
            self._pending_requests[request_id].status = ApprovalStatus.CANCELLED
            del self._pending_requests[request_id]

    def cancel_all(self) -> int:
        """Cancel all pending requests."""
        count = len(self._pending_requests)
        for request in self._pending_requests.values():
            request.status = ApprovalStatus.CANCELLED
        self._pending_requests.clear()
        return count
