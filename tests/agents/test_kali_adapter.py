"""Tests for Kali MCP adapter."""

from __future__ import annotations

import pytest

from src.mcp_adapters.kali_adapter import KaliAdapter
from src.mcp_adapters.base_adapter import MCPResult, MCPError


class TestKaliAdapter:
    """Tests for KaliAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return KaliAdapter(mock_mode=True)

    def test_supported_operations(self, adapter):
        """Test getting supported operations."""
        ops = adapter.get_supported_operations()

        assert "sqlmap_scan" in ops
        assert "nikto_scan" in ops
        assert "hydra_attack" in ops
        assert "dirb_scan" in ops
        assert "wfuzz_scan" in ops
        assert "run_tool" in ops
        assert "list_tools" in ops
        assert "get_tool_help" in ops

    def test_sqlmap_scan(self, adapter):
        """Test SQLMap scan."""
        result = adapter.sqlmap_scan(
            target="http://example.com/page?id=1",
            parameter="id",
        )

        assert result.success is True
        assert "vulnerable" in result.data
        assert result.data["vulnerable"] is True
        assert "injection_type" in result.data

    def test_sqlmap_has_dbms_info(self, adapter):
        """Test SQLMap returns DBMS info."""
        result = adapter.sqlmap_scan(target="http://example.com")

        assert result.success is True
        assert "dbms" in result.data
        assert "payload" in result.data

    def test_nikto_scan(self, adapter):
        """Test Nikto scan."""
        result = adapter.nikto_scan(target="http://example.com")

        assert result.success is True
        assert "findings" in result.data
        assert result.data["total_findings"] > 0

    def test_nikto_findings_have_severity(self, adapter):
        """Test Nikto findings have severity."""
        result = adapter.nikto_scan(target="http://example.com")

        for finding in result.data["findings"]:
            assert "id" in finding
            assert "severity" in finding
            assert "description" in finding

    def test_hydra_attack(self, adapter):
        """Test Hydra credential attack."""
        result = adapter.hydra_attack(
            target="192.168.1.1",
            service="http-post-form",
            username="admin",
        )

        assert result.success is True
        assert result.data["success"] is True
        assert "credentials" in result.data

    def test_hydra_returns_credentials(self, adapter):
        """Test Hydra returns found credentials."""
        result = adapter.hydra_attack(
            target="192.168.1.1",
            service="ssh",
            username="root",
        )

        assert result.success is True
        creds = result.data["credentials"]
        assert "username" in creds
        assert "password" in creds

    def test_dirb_scan(self, adapter):
        """Test DIRB scan."""
        result = adapter.dirb_scan(target="http://example.com")

        assert result.success is True
        assert "directories_found" in result.data
        assert "files_found" in result.data
        assert result.data["total_found"] > 0

    def test_dirb_returns_codes(self, adapter):
        """Test DIRB returns status codes."""
        result = adapter.dirb_scan(target="http://example.com")

        for item in result.data["directories_found"]:
            assert "url" in item
            assert "code" in item

    def test_wfuzz_scan(self, adapter):
        """Test WFuzz scan."""
        result = adapter.wfuzz_scan(
            target="http://example.com/FUZZ",
            wordlist="/usr/share/wordlists/common.txt",
        )

        assert result.success is True
        assert "results" in result.data
        assert "total_requests" in result.data

    def test_run_tool_allowed(self, adapter):
        """Test running allowed tool."""
        result = adapter.run_tool("curl", ["-I", "http://example.com"])

        assert result.success is True
        assert result.data["tool"] == "curl"
        assert result.data["exit_code"] == 0

    def test_run_tool_disallowed(self, adapter):
        """Test running disallowed tool."""
        result = adapter.run_tool("rm", ["-rf", "/"])

        assert result.success is False
        assert "not allowed" in result.error

    def test_list_tools(self, adapter):
        """Test listing available tools."""
        result = adapter.list_tools()

        assert result.success is True
        assert "tools" in result.data
        assert result.data["total"] > 0

    def test_tools_have_categories(self, adapter):
        """Test tools have categories."""
        result = adapter.list_tools()

        for tool in result.data["tools"]:
            assert "name" in tool
            assert "category" in tool
            assert "description" in tool

    def test_get_tool_help(self, adapter):
        """Test getting tool help."""
        result = adapter.get_tool_help("sqlmap")

        assert result.success is True
        assert "help" in result.data
        assert "examples" in result.data

    def test_is_dangerous_operation(self, adapter):
        """Test dangerous operation detection."""
        assert adapter.is_dangerous_operation("sqlmap_scan") is True
        assert adapter.is_dangerous_operation("hydra_attack") is True
        assert adapter.is_dangerous_operation("run_tool") is True
        assert adapter.is_dangerous_operation("list_tools") is False

    def test_result_to_evidence(self, adapter):
        """Test converting result to evidence format."""
        result = adapter.sqlmap_scan(target="http://example.com")

        evidence = result.to_evidence()

        assert evidence["source"] == "kali"
        assert evidence["source_type"] == "mcp_tool"
        assert "data" in evidence


class TestKaliAdapterEdgeCases:
    """Edge case tests for KaliAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return KaliAdapter(mock_mode=True)

    def test_unsupported_operation(self, adapter):
        """Test unsupported operation returns error result."""
        result = adapter.invoke("unsupported_operation", {})

        assert result.success is False
        assert "Unsupported operation" in result.error

    def test_sqlmap_with_options(self, adapter):
        """Test SQLMap with custom options."""
        result = adapter.sqlmap_scan(
            target="http://example.com",
            technique="B",
            level=3,
            risk=2,
        )

        assert result.success is True

    def test_dirb_with_wordlist(self, adapter):
        """Test DIRB with custom wordlist."""
        result = adapter.dirb_scan(
            target="http://example.com",
            wordlist="/custom/wordlist.txt",
        )

        assert result.success is True

    def test_nikto_with_ssl(self, adapter):
        """Test Nikto with SSL."""
        result = adapter.nikto_scan(
            target="example.com",
            port=443,
            ssl=True,
        )

        assert result.success is True
