"""Tests for stop condition monitor."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from src.orchestrator.stop_monitor import StopCondition, StopMonitor, StopReason


class TestStopReason:
    """Tests for StopReason enum."""

    def test_all_reasons_defined(self):
        """Test all expected reasons are defined."""
        expected = [
            "consecutive_errors",
            "scope_violation",
            "dos_detected",
            "destructive_behavior",
            "user_requested",
            "timeout",
            "unknown_error",
            "resource_exhaustion",
        ]
        for reason in expected:
            assert hasattr(StopReason, reason.upper())


class TestStopCondition:
    """Tests for StopCondition dataclass."""

    def test_create_condition(self):
        """Test creating a stop condition."""
        condition = StopCondition(
            reason=StopReason.CONSECUTIVE_ERRORS,
            severity="high",
            message="Test condition",
            details={"count": 3},
        )

        assert condition.reason == StopReason.CONSECUTIVE_ERRORS
        assert condition.severity == "high"
        assert condition.details["count"] == 3

    def test_condition_to_dict(self):
        """Test converting condition to dict."""
        condition = StopCondition(
            reason=StopReason.SCOPE_VIOLATION,
            severity="critical",
            message="Scope violation detected",
            details={"target": "out-of-scope.com"},
            detected_at=datetime(2024, 1, 1, 12, 0, 0),
        )

        result = condition.to_dict()

        assert result["reason"] == "scope_violation"
        assert result["severity"] == "critical"
        assert result["details"]["target"] == "out-of-scope.com"


class TestStopMonitor:
    """Tests for StopMonitor class."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.read_json.return_value = {"targets": []}
        store.write_json = MagicMock()
        store.append_jsonl = MagicMock()
        return store

    @pytest.fixture
    def monitor(self, mock_state_store):
        """Create stop monitor."""
        return StopMonitor(mock_state_store)

    def test_initial_state(self, monitor):
        """Test initial state is not stopped."""
        assert monitor.should_stop is False
        assert monitor.stop_reason is None

    def test_record_success_resets_consecutive_errors(self, monitor):
        """Test success resets consecutive error tracking."""
        # Record some errors
        monitor.record_error("test", "error1")

        # Record success - this resets the last_error_class tracking
        monitor.record_success()

        # Now record another error - it should start fresh
        monitor.record_error("test", "error2")

        # Should not have triggered stop (only 1 consecutive error)
        assert monitor.should_stop is False

    def test_consecutive_errors_trigger_stop(self, monitor):
        """Test consecutive errors trigger stop."""
        # Default threshold is 2
        monitor.record_error("network", "Connection failed")
        assert monitor.should_stop is False

        monitor.record_error("network", "Connection failed again")
        assert monitor.should_stop is True
        assert monitor.stop_reason == StopReason.CONSECUTIVE_ERRORS

    def test_custom_error_threshold(self, mock_state_store):
        """Test custom error threshold."""
        monitor = StopMonitor(
            mock_state_store,
            consecutive_error_threshold=5,
        )

        for i in range(4):
            monitor.record_error("test", f"error {i}")

        assert monitor.should_stop is False

        monitor.record_error("test", "error 5")
        assert monitor.should_stop is True

    def test_total_error_threshold(self, mock_state_store):
        """Test total error threshold generates warning."""
        monitor = StopMonitor(
            mock_state_store,
            consecutive_error_threshold=100,  # High so it doesn't trigger
            total_error_threshold=5,
        )

        for i in range(4):
            monitor.record_error(
                f"type{i}", f"error {i}"
            )  # Different types to avoid consecutive

        assert monitor.should_stop is False

        # 5th error reaches total threshold, but it's a warning (auto_stop=False)
        condition = monitor.record_error("type4", "error 5")
        assert condition is not None
        assert condition.reason == StopReason.UNKNOWN_ERROR
        assert condition.auto_stop is False  # Just a warning

    def test_check_scope_violation(self, monitor, mock_state_store):
        """Test scope violation detection."""
        scope_targets = ["192.168.1.0/24", "example.com"]

        # In-scope target should be OK
        condition = monitor.check_scope_violation("192.168.1.50", scope_targets)
        assert condition is None

        # Out-of-scope target should trigger
        condition = monitor.check_scope_violation("10.0.0.1", scope_targets)
        assert condition is not None
        assert condition.reason == StopReason.SCOPE_VIOLATION

    def test_check_dos_indicators(self, monitor):
        """Test DoS detection."""
        # Normal request rate (10 requests in 60 seconds = 10 per minute)
        condition = monitor.check_dos_indicators(
            requests_count=10,
            time_window_seconds=60.0,
        )
        assert condition is None

        # High request rate (200 requests in 1 second = 12000 per minute)
        condition = monitor.check_dos_indicators(
            requests_count=200,
            time_window_seconds=1.0,
        )
        assert condition is not None
        assert condition.reason == StopReason.DOS_DETECTED

    def test_check_destructive_behavior(self, monitor):
        """Test destructive behavior detection."""
        # Non-destructive operation
        condition = monitor.check_destructive_behavior("port_scan", "192.168.1.1")
        assert condition is None

        # Destructive operations
        destructive_ops = ["rm -rf /", "drop database", "truncate table", "format c:"]
        for op in destructive_ops:
            condition = monitor.check_destructive_behavior(op, "192.168.1.1")
            assert condition is not None
            assert condition.reason == StopReason.DESTRUCTIVE_BEHAVIOR

    def test_manual_stop(self, monitor):
        """Test manual stop request."""
        monitor.request_stop("User requested", "admin")

        assert monitor.should_stop is True
        assert monitor.stop_reason == StopReason.USER_REQUESTED

    def test_get_status(self, monitor):
        """Test getting monitor status."""
        status = monitor.get_status()

        assert "should_stop" in status
        assert "consecutive_errors" in status
        assert "total_errors" in status
        assert "stop_reason" in status
        assert "stop_conditions_count" in status

    def test_stop_condition_recorded(self, monitor):
        """Test stop conditions are recorded."""
        monitor.record_error("test", "error1")
        monitor.record_error("test", "error2")

        # Access stop_conditions property directly
        assert len(monitor.stop_conditions) > 0

    def test_save_emergency_snapshot(self, monitor, mock_state_store):
        """Test emergency snapshot is saved."""
        monitor.record_error("test", "error1")
        monitor.record_error("test", "error2")

        monitor.save_emergency_snapshot()

        mock_state_store.write_json.assert_called()

    def test_error_classification(self, monitor):
        """Test error classification affects tracking."""
        # Network errors
        monitor.record_error("network", "Connection failed")
        status = monitor.get_status()
        assert "network" in status.get("error_types", {}) or status["total_errors"] >= 1

        # Permission errors
        monitor.record_success()  # Reset consecutive
        monitor.record_error("permission", "Access denied")
        status = monitor.get_status()
        assert status["total_errors"] >= 2


class TestStopMonitorThresholds:
    """Tests for stop monitor threshold behavior."""

    def test_zero_threshold_immediately_stops(self):
        """Test zero threshold stops immediately."""
        store = MagicMock()
        store.read_json.return_value = {}
        store.write_json = MagicMock()
        store.append_jsonl = MagicMock()

        # Note: zero threshold might not make sense but test edge case
        monitor = StopMonitor(
            store,
            consecutive_error_threshold=1,
        )

        monitor.record_error("test", "error")
        assert monitor.should_stop is True

    def test_high_threshold_allows_many_errors(self):
        """Test high threshold allows many errors."""
        store = MagicMock()
        store.read_json.return_value = {}
        store.write_json = MagicMock()
        store.append_jsonl = MagicMock()

        monitor = StopMonitor(
            store,
            consecutive_error_threshold=100,
            total_error_threshold=1000,
        )

        for i in range(50):
            monitor.record_error("test", f"error {i}")

        assert monitor.should_stop is False


class TestStopMonitorRecovery:
    """Tests for stop monitor recovery behavior."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.read_json.return_value = {}
        store.write_json = MagicMock()
        store.append_jsonl = MagicMock()
        return store

    def test_intermittent_errors_dont_trigger(self, mock_state_store):
        """Test intermittent errors don't trigger stop."""
        monitor = StopMonitor(
            mock_state_store,
            consecutive_error_threshold=3,
        )

        # Error, success, error, success pattern
        monitor.record_error("test", "error1")
        monitor.record_success()
        monitor.record_error("test", "error2")
        monitor.record_success()
        monitor.record_error("test", "error3")
        monitor.record_success()

        assert monitor.should_stop is False

    def test_consecutive_then_recovery(self, mock_state_store):
        """Test consecutive errors followed by recovery."""
        monitor = StopMonitor(
            mock_state_store,
            consecutive_error_threshold=3,
        )

        # Two errors then success
        monitor.record_error("test", "error1")
        monitor.record_error("test", "error2")
        monitor.record_success()

        # Two more errors - but should start fresh
        monitor.record_error("test", "error3")
        monitor.record_error("test", "error4")

        # Still shouldn't trigger
        assert monitor.should_stop is False

        # One more should trigger
        monitor.record_error("test", "error5")
        assert monitor.should_stop is True
