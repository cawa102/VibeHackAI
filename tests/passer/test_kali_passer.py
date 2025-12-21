"""Tests for Kali Linux Passer."""

from __future__ import annotations

import json
import pytest

from src.passer.kali_passer import KaliPasser
from src.passer.base import MCPType
from src.schemas.execution_result import ExecutionStatus, ErrorClass


class TestKaliPasser:
    """Tests for KaliPasser class."""

    @pytest.fixture
    def passer(self):
        """Create a KaliPasser instance."""
        return KaliPasser(
            session_id="test-session",
            scope_tag="test-scope",
            created_by="test",
        )

    def test_mcp_type(self, passer):
        """Test MCP type is correct."""
        assert passer.mcp_type == MCPType.KALI

    def test_can_handle_kali_json(self, passer):
        """Test can_handle recognizes Kali JSON."""
        data = {"command": "nikto -h 10.0.0.1", "stdout": "output", "exit_code": 0}
        assert passer.can_handle(data) is True

    def test_can_handle_tool_output(self, passer):
        """Test can_handle recognizes tool-specific output."""
        nikto_output = "- Nikto v2.1.6\n+ Target IP: 10.0.0.1"
        assert passer.can_handle(nikto_output) is True

        gobuster_output = "Gobuster v3.1\nFound: /admin (Status: 200)"
        assert passer.can_handle(gobuster_output) is True

    def test_cannot_handle_random_data(self, passer):
        """Test can_handle rejects non-Kali data."""
        assert passer.can_handle({"random": "data"}) is False

    def test_normalize_nikto_output(self, passer):
        """Test normalizing Nikto output."""
        output = """
        - Nikto v2.1.6
        ---------------------------------------------------------------------------
        + Target IP:          10.0.0.1
        + Target Hostname:    10.0.0.1
        + Target Port:        80
        ---------------------------------------------------------------------------
        + Server: Apache/2.4.41 (Ubuntu)
        + The anti-clickjacking X-Frame-Options header is not present.
        + /admin/: Admin login page found.
        + 5 item(s) reported on remote host
        + 1 host(s) tested
        """
        result = passer.normalize(output, tool_name="nikto", plan_id="test-plan", step_index=0)

        assert result.success
        assert len(result.execution_results) == 1
        assert len(result.observations) == 1

        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.SUCCESS
        assert "items reported" in exec_result.output_summary

    def test_normalize_gobuster_output(self, passer):
        """Test normalizing Gobuster output."""
        output = """
        ===============================================================
        Gobuster v3.1.0
        ===============================================================
        /admin                (Status: 200) [Size: 1234]
        /login                (Status: 200) [Size: 567]
        /api                  (Status: 301) [Size: 0]
        ===============================================================
        Finished
        ===============================================================
        """
        result = passer.normalize(output, tool_name="gobuster", plan_id="test-plan", step_index=0)

        assert result.success
        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.SUCCESS
        assert "discovered" in exec_result.output_summary.lower()

    def test_normalize_sqlmap_success(self, passer):
        """Test normalizing SQLMap successful output."""
        output = """
        [INFO] testing connection to the target URL
        [INFO] testing if the target URL is stable
        [INFO] the target URL appears to be stable
        [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
        [INFO] GET parameter 'id' appears to be injectable
        sqlmap identified the following injection points
        database: users
        """
        result = passer.normalize(output, tool_name="sqlmap", plan_id="test-plan", step_index=0)

        assert result.success
        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.SUCCESS
        assert "injection" in exec_result.output_summary.lower() or "database" in exec_result.output_summary.lower()

    def test_normalize_hydra_success(self, passer):
        """Test normalizing Hydra successful output."""
        output = """
        Hydra v9.1 starting...
        [DATA] max 16 tasks per 1 server
        [DATA] attacking ssh://10.0.0.1:22/
        [22][ssh] host: 10.0.0.1   login: admin   password: admin123
        [22][ssh] host: 10.0.0.1   login: root    password: toor
        1 valid passwords found
        """
        result = passer.normalize(output, tool_name="hydra", plan_id="test-plan", step_index=0)

        assert result.success
        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.SUCCESS
        assert "credentials" in exec_result.output_summary.lower()

    def test_normalize_json_format(self, passer):
        """Test normalizing JSON format input."""
        data = {
            "tool": "nikto",
            "command": "nikto -h 10.0.0.1",
            "stdout": "5 item(s) reported on remote host",
            "stderr": "",
            "exit_code": 0,
            "duration": 120,
            "parameters": {"host": "10.0.0.1"},
        }
        result = passer.normalize(data, plan_id="test-plan", step_index=0)

        assert result.success
        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.SUCCESS
        assert exec_result.exit_code == 0
        assert exec_result.command_executed == "nikto -h 10.0.0.1"

    def test_normalize_failure_exit_code(self, passer):
        """Test handling non-zero exit code."""
        data = {
            "tool": "nikto",
            "command": "nikto -h invalid",
            "stdout": "",
            "stderr": "Error: Cannot resolve hostname",
            "exit_code": 1,
        }
        result = passer.normalize(data, plan_id="test-plan", step_index=0)

        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.FAILURE
        assert exec_result.error_class == ErrorClass.TOOL_ERROR

    def test_normalize_timeout_exit_code(self, passer):
        """Test handling timeout exit code."""
        data = {
            "tool": "gobuster",
            "command": "gobuster dir -u http://slow.site",
            "stdout": "",
            "stderr": "timeout",
            "exit_code": 124,  # Standard timeout exit code
        }
        result = passer.normalize(data, plan_id="test-plan", step_index=0)

        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.TIMEOUT
        assert exec_result.error_class == ErrorClass.TIMEOUT

    def test_detect_tool_from_output(self, passer):
        """Test automatic tool detection."""
        assert passer._detect_tool("- Nikto v2.1") == "nikto"
        assert passer._detect_tool("Gobuster v3.1") == "gobuster"
        assert passer._detect_tool("sqlmap identified") == "sqlmap"
        assert passer._detect_tool("Hydra v9.1") == "hydra"
        assert passer._detect_tool("random output") == "unknown"

    def test_error_classification(self, passer):
        """Test error classification."""
        assert passer._classify_error("connection refused") == ErrorClass.NETWORK
        assert passer._classify_error("permission denied") == ErrorClass.PERMISSION
        assert passer._classify_error("not found") == ErrorClass.NOT_FOUND
        assert passer._classify_error("timed out") == ErrorClass.TIMEOUT
        assert passer._classify_error("parse error") == ErrorClass.PARSE
        assert passer._classify_error("something else") == ErrorClass.TOOL_ERROR

    def test_normalize_bytes_input(self, passer):
        """Test normalizing bytes input."""
        output = b"Nikto scan complete\n5 item(s) reported"
        result = passer.normalize(output, tool_name="nikto", plan_id="test-plan", step_index=0)

        assert result.success
        assert len(result.execution_results) == 1
