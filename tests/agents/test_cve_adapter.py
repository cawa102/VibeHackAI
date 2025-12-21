"""Tests for CVE Research MCP adapter."""

from __future__ import annotations

import pytest

from src.mcp_adapters.cve_adapter import CVEAdapter
from src.mcp_adapters.base_adapter import MCPResult, MCPError


class TestCVEAdapter:
    """Tests for CVEAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return CVEAdapter(mock_mode=True)

    def test_supported_operations(self, adapter):
        """Test getting supported operations."""
        ops = adapter.get_supported_operations()

        assert "lookup_cve" in ops
        assert "search_by_product" in ops
        assert "search_by_vendor" in ops
        assert "search_by_keyword" in ops
        assert "get_cve_details" in ops
        assert "get_exploit_info" in ops
        assert "search_recent" in ops

    def test_tool_name(self, adapter):
        """Test tool name is correct."""
        assert adapter.tool_name == "cve_research"

    def test_lookup_cve(self, adapter):
        """Test CVE lookup."""
        result = adapter.lookup_cve("CVE-2021-44228")

        assert result.success is True
        assert result.data["cve_id"] == "CVE-2021-44228"
        assert "description" in result.data
        assert "cvss_v3" in result.data

    def test_lookup_cve_has_cvss_details(self, adapter):
        """Test CVE lookup includes CVSS details."""
        result = adapter.lookup_cve("CVE-2021-44228")

        assert result.success is True
        cvss = result.data["cvss_v3"]
        assert "score" in cvss
        assert "vector" in cvss
        assert "severity" in cvss

    def test_lookup_cve_has_cwe(self, adapter):
        """Test CVE lookup includes CWE info."""
        result = adapter.lookup_cve("CVE-2021-44228")

        assert result.success is True
        assert "cwe" in result.data
        assert len(result.data["cwe"]) > 0

    def test_search_by_product(self, adapter):
        """Test search by product."""
        result = adapter.search_by_product("log4j", "2.14.1")

        assert result.success is True
        assert result.data["product"] == "log4j"
        assert "cves" in result.data
        assert result.data["total"] > 0

    def test_search_by_vendor(self, adapter):
        """Test search by vendor."""
        result = adapter.search_by_vendor("apache")

        assert result.success is True
        assert result.data["vendor"] == "apache"
        assert "cves" in result.data

    def test_search_by_keyword(self, adapter):
        """Test search by keyword."""
        result = adapter.search_by_keyword("log4shell")

        assert result.success is True
        assert result.data["keyword"] == "log4shell"
        assert "cves" in result.data

    def test_get_cve_details(self, adapter):
        """Test getting CVE details."""
        result = adapter.get_cve_details("CVE-2021-44228")

        assert result.success is True
        assert "title" in result.data
        assert "description" in result.data
        assert "cvss_v3" in result.data

    def test_cve_details_has_remediation(self, adapter):
        """Test CVE details includes remediation info."""
        result = adapter.get_cve_details("CVE-2021-44228")

        assert result.success is True
        assert "remediation" in result.data
        remediation = result.data["remediation"]
        assert "recommended_action" in remediation
        assert "workarounds" in remediation

    def test_cve_details_has_exploit_info(self, adapter):
        """Test CVE details includes exploit info."""
        result = adapter.get_cve_details("CVE-2021-44228")

        assert result.success is True
        assert "exploit_info" in result.data
        exploit_info = result.data["exploit_info"]
        assert "public_exploits" in exploit_info

    def test_get_exploit_info(self, adapter):
        """Test getting exploit info for CVE."""
        result = adapter.get_exploit_info("CVE-2021-44228")

        assert result.success is True
        assert result.data["cve_id"] == "CVE-2021-44228"
        assert result.data["exploit_available"] is True
        assert "exploits" in result.data

    def test_exploit_info_has_sources(self, adapter):
        """Test exploit info includes multiple sources."""
        result = adapter.get_exploit_info("CVE-2021-44228")

        assert result.success is True
        exploits = result.data["exploits"]
        sources = {e["source"] for e in exploits}
        assert "exploit-db" in sources or "metasploit" in sources

    def test_search_recent_cves(self, adapter):
        """Test searching recent CVEs."""
        result = adapter.search_recent_cves(days=7)

        assert result.success is True
        assert result.data["days"] == 7
        assert "cves" in result.data

    def test_search_recent_with_severity_filter(self, adapter):
        """Test searching recent CVEs with severity filter."""
        result = adapter.search_recent_cves(days=30, severity="CRITICAL")

        assert result.success is True
        assert result.data["severity_filter"] == "CRITICAL"

    def test_result_to_evidence(self, adapter):
        """Test converting result to evidence format."""
        result = adapter.lookup_cve("CVE-2021-44228")

        evidence = result.to_evidence()

        assert evidence["source"] == "cve_research"
        assert evidence["source_type"] == "mcp_tool"
        assert "data" in evidence


class TestCVEAdapterEdgeCases:
    """Edge case tests for CVEAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return CVEAdapter(mock_mode=True)

    def test_unsupported_operation(self, adapter):
        """Test unsupported operation returns error result."""
        result = adapter.invoke("unsupported_operation", {})

        assert result.success is False
        assert "Unsupported operation" in result.error

    def test_search_without_version(self, adapter):
        """Test product search without version."""
        result = adapter.search_by_product("apache")

        assert result.success is True
        assert result.data["product"] == "apache"

    def test_search_with_vendor_filter(self, adapter):
        """Test product search with vendor filter."""
        result = adapter.search_by_product("log4j", vendor="apache")

        assert result.success is True
