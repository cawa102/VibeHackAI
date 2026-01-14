"""Tests for orchestrator audit logger."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, call
from datetime import datetime

from src.orchestrator.audit_logger import (
    OrchestratorAuditLogger,
    AuditEvent,
    AuditEventType,
)


class TestAuditEventType:
    """Tests for AuditEventType enum."""

    def test_all_event_types_defined(self):
        """Test all expected event types are defined."""
        expected = [
            "session_start",
            "session_end",
            "phase_transition",
            "agent_invoked",
            "agent_completed",
            "agent_failed",
            "approval_requested",
            "approval_granted",
            "approval_denied",
            "patch_received",
            "patch_applied",
            "patch_rejected",
            "stop_condition",
            "error",
        ]
        for event_type in expected:
            assert hasattr(AuditEventType, event_type.upper())


class TestAuditEvent:
    """Tests for AuditEvent dataclass."""

    def test_create_event(self):
        """Test creating an audit event."""
        event = AuditEvent(
            event_id="evt-001",
            event_type=AuditEventType.SESSION_START,
            timestamp=datetime.utcnow(),
            session_id="session-001",
        )

        assert event.event_id == "evt-001"
        assert event.event_type == AuditEventType.SESSION_START
        assert event.session_id == "session-001"

    def test_event_with_details(self):
        """Test creating event with details."""
        event = AuditEvent(
            event_id="evt-002",
            event_type=AuditEventType.AGENT_INVOKED,
            timestamp=datetime.utcnow(),
            session_id="session-001",
            details={"agent": "recon_agent", "phase": "recon"},
        )

        assert event.details["agent"] == "recon_agent"
        assert event.details["phase"] == "recon"

    def test_event_to_dict(self):
        """Test converting event to dict."""
        event = AuditEvent(
            event_id="evt-003",
            event_type=AuditEventType.PHASE_TRANSITION,
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            session_id="session-001",
            details={"from": "recon", "to": "enumeration"},
        )

        result = event.to_dict()

        assert result["event_id"] == "evt-003"
        assert result["event_type"] == "phase_transition"
        assert result["session_id"] == "session-001"
        assert result["details"]["from"] == "recon"


class TestOrchestratorAuditLogger:
    """Tests for OrchestratorAuditLogger class."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.append_jsonl = MagicMock()
        return store

    @pytest.fixture
    def logger(self, mock_state_store):
        """Create audit logger."""
        return OrchestratorAuditLogger(
            mock_state_store,
            session_id="test-session",
        )

    def test_log_session_start(self, logger, mock_state_store):
        """Test logging session start."""
        logger.log_session_start("scope-tag-1", details={"config": "test"})

        mock_state_store.append_jsonl.assert_called_once()
        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "session_start"
        assert "scope_tag" in event_data["details"]

    def test_log_session_end(self, logger, mock_state_store):
        """Test logging session end."""
        logger.log_session_end("Normal completion")

        mock_state_store.append_jsonl.assert_called_once()
        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "session_end"
        assert event_data["details"]["reason"] == "Normal completion"

    def test_log_phase_transition(self, logger, mock_state_store):
        """Test logging phase transition."""
        logger.log_phase_transition("recon", "enumeration", "Normal advance")

        mock_state_store.append_jsonl.assert_called_once()
        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "phase_transition"
        assert event_data["details"]["from_phase"] == "recon"
        assert event_data["details"]["to_phase"] == "enumeration"

    def test_log_agent_invoked(self, logger, mock_state_store):
        """Test logging agent invocation."""
        logger.log_agent_invoked("recon_agent", "recon", context_size=1024)

        mock_state_store.append_jsonl.assert_called_once()
        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "agent_invoked"
        assert event_data["details"]["agent_type"] == "recon_agent"
        assert event_data["details"]["context_size"] == 1024

    def test_log_agent_completed(self, logger, mock_state_store):
        """Test logging agent completion."""
        logger.log_agent_completed("recon_agent", "recon", success=True, duration_ms=5000)

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "agent_completed"
        assert event_data["details"]["success"] is True
        assert event_data["details"]["duration_ms"] == 5000

    def test_log_agent_failed(self, logger, mock_state_store):
        """Test logging agent failure."""
        logger.log_agent_failed("recon_agent", "recon", "Connection timeout")

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "agent_failed"
        assert event_data["details"]["error"] == "Connection timeout"

    def test_log_approval_requested(self, logger, mock_state_store):
        """Test logging approval request."""
        logger.log_approval_requested("req-001", "metasploit_execute", "192.168.1.1")

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "approval_requested"
        assert event_data["details"]["request_id"] == "req-001"
        assert event_data["details"]["operation"] == "metasploit_execute"

    def test_log_approval_granted(self, logger, mock_state_store):
        """Test logging approval granted."""
        logger.log_approval_granted("req-001", "admin")

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "approval_granted"
        assert event_data["details"]["responded_by"] == "admin"

    def test_log_approval_denied(self, logger, mock_state_store):
        """Test logging approval denied."""
        logger.log_approval_denied("req-001", "admin", "Too risky")

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "approval_denied"
        assert event_data["details"]["reason"] == "Too risky"

    def test_log_patch_received(self, logger, mock_state_store):
        """Test logging patch received."""
        logger.log_patch_received("patch-001", "recon_agent", 5)

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "patch_received"
        assert event_data["details"]["patch_id"] == "patch-001"
        assert event_data["details"]["operation_count"] == 5

    def test_log_patch_applied(self, logger, mock_state_store):
        """Test logging patch applied."""
        logger.log_patch_applied("patch-001", 5, 3)

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "patch_applied"
        assert event_data["details"]["operations_applied"] == 5
        assert event_data["details"]["new_version"] == 3

    def test_log_patch_rejected(self, logger, mock_state_store):
        """Test logging patch rejected."""
        logger.log_patch_rejected(
            "patch-001",
            "Validation failed",
            ["invalid operation", "missing field"],
        )

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "patch_rejected"
        assert event_data["details"]["error"] == "Validation failed"
        assert len(event_data["details"]["validation_errors"]) == 2

    def test_log_stop_condition(self, logger, mock_state_store):
        """Test logging stop condition."""
        logger.log_stop_condition(
            "consecutive_errors",
            "high",
            {"count": 3},
        )

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "stop_condition"
        assert event_data["details"]["reason"] == "consecutive_errors"
        assert event_data["details"]["severity"] == "high"

    def test_log_error(self, logger, mock_state_store):
        """Test logging error."""
        logger.log_error("Something went wrong")

        call_args = mock_state_store.append_jsonl.call_args
        event_data = call_args[0][1]

        assert event_data["event_type"] == "error"
        assert event_data["details"]["message"] == "Something went wrong"

    def test_count_events(self, logger, mock_state_store):
        """Test counting events."""
        # Log several events
        logger.log_session_start("scope")
        logger.log_phase_transition("init", "recon", "start")
        logger.log_agent_invoked("recon_agent", "recon")

        count = logger.count_events()
        assert count == 3

    def test_event_ids_unique(self, logger, mock_state_store):
        """Test event IDs are unique."""
        event_ids = set()

        for _ in range(10):
            logger.log_error("test")
            call_args = mock_state_store.append_jsonl.call_args
            event_data = call_args[0][1]
            event_ids.add(event_data["event_id"])

        assert len(event_ids) == 10

    def test_session_id_in_all_events(self, logger, mock_state_store):
        """Test session ID is in all events."""
        logger.log_session_start("scope")
        logger.log_phase_transition("a", "b", "reason")
        logger.log_agent_invoked("agent", "phase")

        for call in mock_state_store.append_jsonl.call_args_list:
            event_data = call[0][1]
            assert event_data["session_id"] == "test-session"


class TestAuditLoggerQuery:
    """Tests for audit logger query functionality."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store with events."""
        store = MagicMock()
        store.append_jsonl = MagicMock()
        store.read_jsonl.return_value = [
            {
                "event_id": "evt-001",
                "event_type": "session_start",
                "session_id": "test-session",
                "timestamp": "2024-01-01T12:00:00",
                "details": {},
            },
            {
                "event_id": "evt-002",
                "event_type": "phase_transition",
                "session_id": "test-session",
                "timestamp": "2024-01-01T12:01:00",
                "details": {"from_phase": "init", "to_phase": "recon"},
            },
        ]
        return store

    def test_get_events(self, mock_state_store):
        """Test getting all events."""
        logger = OrchestratorAuditLogger(mock_state_store, "test-session")

        events = logger.get_events()

        assert len(events) == 2
        mock_state_store.read_jsonl.assert_called_once()

    def test_get_events_by_type(self, mock_state_store):
        """Test filtering events by type."""
        logger = OrchestratorAuditLogger(mock_state_store, "test-session")

        events = logger.get_events(event_type=AuditEventType.PHASE_TRANSITION)

        # Should filter to just phase transitions
        assert all(e.get("event_type") == "phase_transition" for e in events)
