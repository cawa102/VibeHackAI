"""Tests for Metasploit MCP adapter."""

from __future__ import annotations

import pytest

from src.mcp_adapters.metasploit_adapter import MetasploitAdapter
from src.mcp_adapters.base_adapter import MCPResult, MCPError


class TestMetasploitAdapter:
    """Tests for MetasploitAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return MetasploitAdapter(mock_mode=True)

    def test_supported_operations(self, adapter):
        """Test getting supported operations."""
        ops = adapter.get_supported_operations()

        assert "search_modules" in ops
        assert "get_module_info" in ops
        assert "set_options" in ops
        assert "execute_exploit" in ops
        assert "check_vuln" in ops
        assert "list_sessions" in ops
        assert "session_command" in ops
        assert "close_session" in ops
        assert "get_payloads" in ops

    def test_search_modules(self, adapter):
        """Test module search."""
        result = adapter.search_modules("log4j")

        assert result.success is True
        assert "modules" in result.data
        assert result.data["total"] > 0

    def test_modules_have_metadata(self, adapter):
        """Test modules have metadata."""
        result = adapter.search_modules("apache")

        assert result.success is True
        for module in result.data["modules"]:
            assert "name" in module
            assert "rank" in module
            assert "description" in module

    def test_get_module_info(self, adapter):
        """Test getting module info."""
        result = adapter.get_module_info("exploit/multi/http/log4shell_header_injection")

        assert result.success is True
        assert "name" in result.data
        assert "options" in result.data
        assert "targets" in result.data

    def test_module_info_has_options(self, adapter):
        """Test module info has options."""
        result = adapter.get_module_info("exploit/test")

        assert result.success is True
        options = result.data["options"]
        assert "RHOSTS" in options
        assert options["RHOSTS"]["required"] is True

    def test_set_options(self, adapter):
        """Test setting module options."""
        result = adapter.set_options(
            module="exploit/test",
            options={"RHOSTS": "192.168.1.1", "RPORT": 8080},
        )

        assert result.success is True
        assert result.data["validation"]["valid"] is True

    def test_execute_exploit_dry_run(self, adapter):
        """Test exploit execution in dry run mode."""
        result = adapter.execute_exploit(
            module="exploit/test",
            target="192.168.1.1",
            dry_run=True,
        )

        assert result.success is True
        assert result.data["dry_run"] is True
        assert "command_preview" in result.data

    def test_execute_exploit(self, adapter):
        """Test exploit execution."""
        result = adapter.execute_exploit(
            module="exploit/test",
            target="192.168.1.1",
        )

        assert result.success is True
        assert result.data["result"] == "success"
        assert "session_id" in result.data

    def test_check_vulnerability(self, adapter):
        """Test vulnerability check."""
        result = adapter.check_vulnerability(
            module="exploit/test",
            target="192.168.1.1",
        )

        assert result.success is True
        assert "vulnerable" in result.data
        assert "confidence" in result.data

    def test_list_sessions(self, adapter):
        """Test listing sessions."""
        # Execute exploit first to create session
        adapter.execute_exploit(module="test", target="192.168.1.1")

        result = adapter.list_sessions()

        assert result.success is True
        assert "sessions" in result.data
        assert result.data["total"] >= 1

    def test_session_command(self, adapter):
        """Test running session command."""
        # Create session
        exploit_result = adapter.execute_exploit(module="test", target="192.168.1.1")
        session_id = exploit_result.data["session_id"]

        result = adapter.run_session_command(session_id, "whoami")

        assert result.success is True
        assert result.data["command"] == "whoami"
        assert "output" in result.data

    def test_session_command_invalid_session(self, adapter):
        """Test session command with invalid session."""
        result = adapter.run_session_command("invalid-session", "whoami")

        assert result.success is False
        assert "not found" in result.error

    def test_close_session(self, adapter):
        """Test closing session."""
        # Create session
        exploit_result = adapter.execute_exploit(module="test", target="192.168.1.1")
        session_id = exploit_result.data["session_id"]

        result = adapter.close_session(session_id)

        assert result.success is True
        assert result.data["closed"] is True

    def test_get_payloads(self, adapter):
        """Test getting compatible payloads."""
        result = adapter.get_payloads(module="exploit/test", platform="linux")

        assert result.success is True
        assert "payloads" in result.data
        assert result.data["total"] > 0

    def test_payloads_have_info(self, adapter):
        """Test payloads have info."""
        result = adapter.get_payloads(module="exploit/test")

        for payload in result.data["payloads"]:
            assert "name" in payload
            assert "description" in payload

    def test_is_dangerous_operation(self, adapter):
        """Test dangerous operation detection."""
        assert adapter.is_dangerous_operation("execute_exploit") is True
        assert adapter.is_dangerous_operation("session_command") is True
        assert adapter.is_dangerous_operation("search_modules") is False

    def test_result_to_evidence(self, adapter):
        """Test converting result to evidence format."""
        result = adapter.search_modules("test")

        evidence = result.to_evidence()

        assert evidence["source"] == "metasploit"
        assert evidence["source_type"] == "mcp_tool"
        assert "data" in evidence


class TestMetasploitAdapterEdgeCases:
    """Edge case tests for MetasploitAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return MetasploitAdapter(mock_mode=True)

    def test_unsupported_operation(self, adapter):
        """Test unsupported operation returns error result."""
        result = adapter.invoke("unsupported_operation", {})

        assert result.success is False
        assert "Unsupported operation" in result.error

    def test_execute_with_options(self, adapter):
        """Test execute with custom options."""
        result = adapter.execute_exploit(
            module="exploit/test",
            target="192.168.1.1",
            options={"PAYLOAD": "linux/x64/meterpreter/reverse_tcp"},
        )

        assert result.success is True

    def test_multiple_sessions(self, adapter):
        """Test handling multiple sessions."""
        # Create multiple sessions
        adapter.execute_exploit(module="test1", target="192.168.1.1")
        adapter.execute_exploit(module="test2", target="192.168.1.2")

        result = adapter.list_sessions()

        assert result.success is True
        assert result.data["total"] >= 2
