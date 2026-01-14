"""Tests for CLI display utilities."""

from __future__ import annotations

import pytest

from src.cli.display import Display


class TestDisplay:
    """Tests for Display class."""

    @pytest.fixture
    def display(self):
        """Create display with colors."""
        return Display(use_colors=True)

    @pytest.fixture
    def display_no_colors(self):
        """Create display without colors."""
        return Display(use_colors=False)

    def test_header(self, display):
        """Test header formatting."""
        result = display.header("Test Header")

        assert "Test Header" in result
        assert "=" in result

    def test_header_no_colors(self, display_no_colors):
        """Test header without colors."""
        result = display_no_colors.header("Test Header")

        assert "Test Header" in result
        # No ANSI codes
        assert "\033[" not in result

    def test_subheader(self, display):
        """Test subheader formatting."""
        result = display.subheader("Sub Header")

        assert "Sub Header" in result
        assert "---" in result

    def test_success(self, display):
        """Test success message."""
        result = display.success("Operation complete")

        assert "[+]" in result
        assert "Operation complete" in result

    def test_error(self, display):
        """Test error message."""
        result = display.error("Something failed")

        assert "[-]" in result
        assert "Something failed" in result

    def test_warning(self, display):
        """Test warning message."""
        result = display.warning("Be careful")

        assert "[!]" in result
        assert "Be careful" in result

    def test_info(self, display):
        """Test info message."""
        result = display.info("FYI")

        assert "[*]" in result
        assert "FYI" in result

    def test_phase(self, display):
        """Test phase display."""
        result = display.phase("recon", "active")

        assert "Phase:" in result
        assert "recon" in result
        assert "active" in result

    def test_phase_no_status(self, display):
        """Test phase display without status."""
        result = display.phase("enumeration")

        assert "enumeration" in result

    def test_progress(self, display):
        """Test progress bar."""
        result = display.progress(50, 100)

        assert "50/100" in result
        assert "50.0%" in result
        assert "█" in result

    def test_progress_zero_total(self, display):
        """Test progress with zero total."""
        result = display.progress(0, 0)

        assert "0/0" in result
        assert "0.0%" in result

    def test_progress_complete(self, display):
        """Test complete progress bar."""
        result = display.progress(100, 100)

        assert "100/100" in result
        assert "100.0%" in result


class TestDisplayTable:
    """Tests for table formatting."""

    @pytest.fixture
    def display(self):
        """Create display."""
        return Display(use_colors=False)

    def test_simple_table(self, display):
        """Test simple table."""
        headers = ["Name", "Value"]
        rows = [["foo", "bar"], ["baz", "qux"]]

        result = display.table(headers, rows)

        assert "Name" in result
        assert "Value" in result
        assert "foo" in result
        assert "bar" in result

    def test_empty_table(self, display):
        """Test empty table."""
        headers = ["Name"]
        rows = []

        result = display.table(headers, rows)

        assert result == ""

    def test_table_alignment(self, display):
        """Test table alignment."""
        headers = ["Left", "Center", "Right"]
        rows = [["a", "b", "c"]]
        alignments = ["l", "c", "r"]

        result = display.table(headers, rows, alignments)

        # Should have content
        assert "Left" in result
        assert "Center" in result
        assert "Right" in result


class TestDisplayKeyValue:
    """Tests for key-value formatting."""

    @pytest.fixture
    def display(self):
        """Create display."""
        return Display(use_colors=False)

    def test_simple_key_value(self, display):
        """Test simple key-value pairs."""
        items = {"Name": "Test", "Version": "1.0"}

        result = display.key_value(items)

        assert "Name:" in result
        assert "Test" in result
        assert "Version:" in result
        assert "1.0" in result

    def test_nested_key_value(self, display):
        """Test nested key-value pairs."""
        items = {
            "Config": {
                "Host": "localhost",
                "Port": 8080,
            }
        }

        result = display.key_value(items)

        assert "Config:" in result
        assert "Host:" in result
        assert "localhost" in result

    def test_list_key_value(self, display):
        """Test key-value with list."""
        items = {
            "Targets": ["192.168.1.1", "192.168.1.2"]
        }

        result = display.key_value(items)

        assert "Targets:" in result
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result


class TestDisplayApprovalRequest:
    """Tests for approval request display."""

    @pytest.fixture
    def display(self):
        """Create display."""
        return Display(use_colors=False)

    def test_approval_request(self, display):
        """Test approval request display."""
        result = display.approval_request(
            operation="metasploit_execute",
            target="192.168.1.1",
            risk_level="high",
        )

        assert "APPROVAL REQUIRED" in result
        assert "Operation:" in result
        assert "metasploit_execute" in result
        assert "Target:" in result
        assert "192.168.1.1" in result
        assert "Risk Level:" in result
        assert "HIGH" in result

    def test_approval_request_with_details(self, display):
        """Test approval request with details."""
        result = display.approval_request(
            operation="exploit_execute",
            target="10.0.0.1",
            risk_level="critical",
            details={
                "CVE": "CVE-2024-1234",
                "Payload": "reverse_shell",
            },
        )

        assert "Details:" in result
        assert "CVE: CVE-2024-1234" in result
        assert "Payload: reverse_shell" in result


class TestDisplayStatus:
    """Tests for status display."""

    @pytest.fixture
    def display(self):
        """Create display."""
        return Display(use_colors=False)

    def test_status_display(self, display):
        """Test status display."""
        status = {
            "session_id": "sess-001",
            "scope_tag": "test",
            "current_phase": "recon",
            "is_running": True,
            "state_version": 5,
            "pending_approvals": 2,
            "audit_events_count": 15,
        }

        result = display.status_display(status)

        assert "Session ID:" in result
        assert "sess-001" in result
        assert "Current Phase:" in result
        assert "recon" in result
        assert "Running:" in result

    def test_status_display_stopped(self, display):
        """Test status display when stopped."""
        status = {
            "session_id": "sess-001",
            "scope_tag": "test",
            "current_phase": "stopped",
            "is_running": False,
            "state_version": 3,
            "pending_approvals": 0,
            "audit_events_count": 10,
            "stop_monitor_status": {
                "should_stop": True,
                "stop_reason": "consecutive_errors",
            },
        }

        result = display.status_display(status)

        assert "STOPPED:" in result
        assert "consecutive_errors" in result


class TestDisplayFinding:
    """Tests for finding display."""

    @pytest.fixture
    def display(self):
        """Create display."""
        return Display(use_colors=False)

    def test_finding_display(self, display):
        """Test finding display."""
        finding = {
            "title": "SQL Injection",
            "severity": "high",
            "affected_component": "login.php",
            "description": "SQL injection vulnerability in login form parameter",
        }

        result = display.finding_display(finding)

        assert "Title:" in result
        assert "SQL Injection" in result
        assert "Severity:" in result
        assert "HIGH" in result
        assert "Affected:" in result
        assert "login.php" in result

    def test_finding_severity_colors(self):
        """Test finding severity colors."""
        display = Display(use_colors=True)

        for severity in ["critical", "high", "medium", "low", "info"]:
            finding = {
                "title": "Test",
                "severity": severity,
                "affected_component": "test",
            }
            result = display.finding_display(finding)
            assert severity.upper() in result


class TestDisplaySpinner:
    """Tests for spinner animation."""

    def test_spinner_frames(self):
        """Test spinner frames."""
        display = Display()
        frames = display.spinner_frames()

        assert len(frames) > 0
        assert all(isinstance(f, str) for f in frames)
