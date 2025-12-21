"""Tests for approval gate."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from datetime import datetime

from src.orchestrator.approval_gate import (
    ApprovalGate,
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
    APPROVAL_REQUIRED_OPERATIONS,
    APPROVAL_REQUIRED_TOOLS,
)


class TestApprovalStatus:
    """Tests for ApprovalStatus enum."""

    def test_all_statuses_defined(self):
        """Test all expected statuses are defined."""
        expected = ["pending", "approved", "rejected", "timeout", "cancelled"]
        for status_name in expected:
            assert hasattr(ApprovalStatus, status_name.upper())


class TestApprovalRequest:
    """Tests for ApprovalRequest dataclass."""

    def test_create_request(self):
        """Test creating an approval request."""
        request = ApprovalRequest(
            request_id="req-001",
            operation="metasploit_execute",
            target="192.168.1.100",
            created_at=datetime.utcnow(),
        )

        assert request.request_id == "req-001"
        assert request.operation == "metasploit_execute"
        assert request.target == "192.168.1.100"
        assert request.status == ApprovalStatus.PENDING

    def test_request_to_dict(self):
        """Test converting request to dict."""
        request = ApprovalRequest(
            request_id="req-001",
            operation="exploit_verify",
            target="10.0.0.1",
            created_at=datetime(2024, 1, 1, 12, 0, 0),
            description="Verify SQL injection",
            risk_level="high",
        )

        result = request.to_dict()

        assert result["request_id"] == "req-001"
        assert result["operation"] == "exploit_verify"
        assert result["target"] == "10.0.0.1"
        assert result["risk_level"] == "high"
        assert result["status"] == "pending"


class TestApprovalResult:
    """Tests for ApprovalResult dataclass."""

    def test_create_approved_result(self):
        """Test creating approved result."""
        result = ApprovalResult(
            request_id="req-001",
            approved=True,
            responded_by="user",
            responded_at=datetime.utcnow(),
        )

        assert result.approved is True
        assert result.responded_by == "user"

    def test_create_rejected_result(self):
        """Test creating rejected result."""
        result = ApprovalResult(
            request_id="req-001",
            approved=False,
            responded_by="admin",
            reason="Too risky",
        )

        assert result.approved is False
        assert result.reason == "Too risky"


class TestApprovalGate:
    """Tests for ApprovalGate class."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.append_jsonl = MagicMock()
        return store

    @pytest.fixture
    def gate(self, mock_state_store):
        """Create approval gate."""
        return ApprovalGate(mock_state_store)

    def test_requires_approval_for_dangerous_operations(self, gate):
        """Test dangerous operations require approval."""
        for op in APPROVAL_REQUIRED_OPERATIONS:
            assert gate.requires_approval(operation=op) is True

    def test_requires_approval_for_dangerous_tools(self, gate):
        """Test dangerous tools require approval."""
        for tool in APPROVAL_REQUIRED_TOOLS:
            assert gate.requires_approval(tool=tool) is True

    def test_no_approval_for_safe_operations(self, gate):
        """Test safe operations don't require approval."""
        safe_ops = ["port_scan", "dns_lookup", "whois_query"]
        for op in safe_ops:
            # These should not require approval unless explicitly listed
            if op not in APPROVAL_REQUIRED_OPERATIONS:
                assert gate.requires_approval(operation=op) is False

    def test_create_request(self, gate):
        """Test creating an approval request."""
        request = gate.create_request(
            operation="metasploit_execute",
            target="192.168.1.1",
            description="Run exploit",
        )

        assert request.operation == "metasploit_execute"
        assert request.target == "192.168.1.1"
        assert request.request_id.startswith("apr-")

    def test_create_request_with_risk_level(self, gate):
        """Test creating request with risk level."""
        request = gate.create_request(
            operation="brute_force",
            target="ssh://10.0.0.1:22",
            risk_level="high",
        )

        assert request.risk_level == "high"

    def test_pending_request_tracking(self, gate):
        """Test pending requests are tracked."""
        request = gate.create_request(
            operation="payload_deliver",
            target="10.0.0.1",
        )

        pending = gate.get_pending_requests()
        assert len(pending) == 1
        assert pending[0].request_id == request.request_id

    def test_approve_request(self, gate):
        """Test approving a request."""
        request = gate.create_request(
            operation="metasploit_execute",
            target="10.0.0.1",
        )

        result = gate.approve(request.request_id, "admin")

        assert result.approved is True
        assert result.responded_by == "admin"

        # Should no longer be pending
        pending = gate.get_pending_requests()
        assert len(pending) == 0

    def test_reject_request(self, gate):
        """Test rejecting a request."""
        request = gate.create_request(
            operation="brute_force",
            target="10.0.0.1",
        )

        result = gate.reject(request.request_id, "admin", "Too risky")

        assert result.approved is False
        assert result.reason == "Too risky"

        # Should no longer be pending
        pending = gate.get_pending_requests()
        assert len(pending) == 0

    def test_approve_nonexistent_request(self, gate):
        """Test approving non-existent request."""
        result = gate.approve("fake-id", "admin")
        assert result is None

    def test_reject_nonexistent_request(self, gate):
        """Test rejecting non-existent request."""
        result = gate.reject("fake-id", "admin", "reason")
        assert result is None

    def test_cancel_request(self, gate):
        """Test cancelling a request."""
        request = gate.create_request(
            operation="exploit_execute",
            target="10.0.0.1",
        )

        gate.cancel(request.request_id)

        pending = gate.get_pending_requests()
        assert len(pending) == 0

    def test_get_request_by_id(self, gate):
        """Test getting request by ID."""
        request = gate.create_request(
            operation="test_op",
            target="test_target",
        )

        found = gate.get_request(request.request_id)
        assert found is not None
        assert found.request_id == request.request_id

    def test_get_nonexistent_request(self, gate):
        """Test getting non-existent request."""
        found = gate.get_request("fake-id")
        assert found is None


class TestApprovalCallback:
    """Tests for approval callback functionality."""

    def test_request_approval_with_callback(self):
        """Test requesting approval with callback."""
        store = MagicMock()

        # Create callback that auto-approves
        def auto_approve(request):
            return ApprovalResult(
                request_id=request.request_id,
                approved=True,
                responded_by="auto",
                responded_at=datetime.utcnow(),
            )

        gate = ApprovalGate(store, approval_callback=auto_approve)

        request = gate.create_request(
            operation="metasploit_execute",
            target="10.0.0.1",
        )

        result = gate.request_approval(request)

        assert result.approved is True
        assert result.responded_by == "auto"

    def test_request_approval_with_rejecting_callback(self):
        """Test requesting approval with rejecting callback."""
        store = MagicMock()

        def auto_reject(request):
            return ApprovalResult(
                request_id=request.request_id,
                approved=False,
                responded_by="auto",
                reason="Auto-rejected",
            )

        gate = ApprovalGate(store, approval_callback=auto_reject)

        request = gate.create_request(
            operation="brute_force",
            target="10.0.0.1",
        )

        result = gate.request_approval(request)

        assert result.approved is False
        assert result.reason == "Auto-rejected"


class TestApprovalRequirements:
    """Tests for approval requirement sets."""

    def test_dangerous_operations_defined(self):
        """Test dangerous operations are defined."""
        expected_ops = [
            "metasploit_execute",
            "payload_deliver",
            "brute_force",
            "exploit_execute",
        ]
        for op in expected_ops:
            assert op in APPROVAL_REQUIRED_OPERATIONS

    def test_dangerous_tools_defined(self):
        """Test dangerous tools are defined."""
        expected_tools = [
            "metasploit",
            "hydra",
            "hashcat",
        ]
        for tool in expected_tools:
            assert tool in APPROVAL_REQUIRED_TOOLS
