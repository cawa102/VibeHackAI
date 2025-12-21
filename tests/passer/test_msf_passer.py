"""Tests for Metasploit Passer."""

from __future__ import annotations

import json
import pytest

from src.passer.msf_passer import MetasploitPasser
from src.passer.base import MCPType
from src.schemas.execution_result import ExecutionStatus


class TestMetasploitPasser:
    """Tests for MetasploitPasser class."""

    @pytest.fixture
    def passer(self):
        """Create a MetasploitPasser instance."""
        return MetasploitPasser(
            session_id="test-session",
            scope_tag="test-scope",
            created_by="test",
        )

    def test_mcp_type(self, passer):
        """Test MCP type is correct."""
        assert passer.mcp_type == MCPType.METASPLOIT

    def test_can_handle_msf_json(self, passer):
        """Test can_handle recognizes MSF JSON."""
        data = {"module": "exploit/windows/smb/ms17_010", "job_id": 1}
        assert passer.can_handle(data) is True

    def test_can_handle_console_output(self, passer):
        """Test can_handle recognizes console output."""
        output = """
        msf6 > use exploit/windows/smb/ms17_010
        msf6 exploit(windows/smb/ms17_010) > set RHOSTS 10.0.0.1
        [*] Starting exploit...
        [+] Meterpreter session 1 opened
        """
        assert passer.can_handle(output) is True

    def test_cannot_handle_random_data(self, passer):
        """Test can_handle rejects non-MSF data."""
        assert passer.can_handle({"random": "data"}) is False
        assert passer.can_handle("random string without msf keywords") is False

    def test_normalize_successful_exploit_console(self, passer):
        """Test normalizing successful exploit console output."""
        output = """
        [*] Started reverse TCP handler on 10.0.0.100:4444
        [*] 10.0.0.1:445 - Connecting to target for exploitation.
        [+] 10.0.0.1:445 - Connection established for exploitation.
        [+] 10.0.0.1:445 - Target OS selected valid for OS indicated by SMB reply
        [*] 10.0.0.1:445 - CORE raw buffer dump (42 bytes)
        [+] Meterpreter session 1 opened (10.0.0.100:4444 -> 10.0.0.1:49159)
        """
        result = passer.normalize(output, plan_id="test-plan", step_index=0)

        assert result.success
        assert len(result.execution_results) == 1

        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.SUCCESS
        assert "session 1" in exec_result.output_summary.lower()

    def test_normalize_failed_exploit_console(self, passer):
        """Test normalizing failed exploit console output."""
        output = """
        [*] Started reverse TCP handler on 10.0.0.100:4444
        [*] 10.0.0.1:445 - Connecting to target for exploitation.
        [-] 10.0.0.1:445 - Exploit failed: No session was created
        [-] Exploit failed
        """
        result = passer.normalize(output, plan_id="test-plan", step_index=0)

        assert len(result.execution_results) == 1
        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.FAILURE

    def test_normalize_module_result_json(self, passer):
        """Test normalizing JSON module result."""
        data = {
            "module_name": "exploit/windows/smb/ms17_010",
            "module_type": "exploit",
            "job_id": 1,
            "uuid": "abc-123",
            "result": "success",
            "options": {
                "RHOSTS": "10.0.0.1",
                "RPORT": 445,
            },
        }
        result = passer.normalize(data, plan_id="test-plan", step_index=0)

        assert result.success
        assert len(result.execution_results) == 1

        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.SUCCESS
        assert exec_result.parameters_used == {"RHOSTS": "10.0.0.1", "RPORT": 445}

    def test_normalize_sessions_json(self, passer):
        """Test normalizing sessions JSON."""
        data = {
            "sessions": {
                "1": {
                    "type": "meterpreter",
                    "target_host": "10.0.0.1",
                    "tunnel_peer": "10.0.0.1:49159",
                    "via_exploit": "exploit/windows/smb/ms17_010",
                    "via_payload": "windows/x64/meterpreter/reverse_tcp",
                    "platform": "windows",
                    "arch": "x64",
                },
                "2": {
                    "type": "shell",
                    "target_host": "10.0.0.2",
                    "tunnel_peer": "10.0.0.2:49160",
                },
            },
        }
        result = passer.normalize(data, plan_id="test-plan", step_index=0)

        assert result.success
        assert len(result.execution_results) == 2

        # Check first session
        session1 = result.execution_results[0]
        assert session1.status == ExecutionStatus.SUCCESS
        assert session1.metadata["session_type"] == "meterpreter"
        assert session1.metadata["platform"] == "windows"

    def test_normalize_module_failure_json(self, passer):
        """Test normalizing failed module JSON."""
        data = {
            "module_name": "exploit/test",
            "result": "failure",
            "error": True,
            "error_message": "Connection refused",
        }
        result = passer.normalize(data, plan_id="test-plan", step_index=0)

        exec_result = result.execution_results[0]
        assert exec_result.status == ExecutionStatus.FAILURE
        assert "Connection refused" in (exec_result.error_message or "")

    def test_extract_session_info(self, passer):
        """Test extracting session info from output."""
        output = "Meterpreter session 5 opened (10.0.0.1:4444 -> 10.0.0.2:49159)"
        info = passer._extract_session_info(output)

        assert info is not None
        assert info["type"] == "Meterpreter"
        assert info["id"] == "5"
        assert info["connection"] == "10.0.0.1:4444 -> 10.0.0.2:49159"

    def test_normalize_bytes_input(self, passer):
        """Test normalizing bytes input."""
        output = b"[+] Meterpreter session 1 opened"
        result = passer.normalize(output, plan_id="test-plan", step_index=0)

        assert len(result.execution_results) == 1
        assert result.execution_results[0].status == ExecutionStatus.SUCCESS
