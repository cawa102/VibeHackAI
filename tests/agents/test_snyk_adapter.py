"""Tests for Snyk MCP adapter."""

from __future__ import annotations

import pytest

from src.mcp_adapters.snyk_adapter import SnykAdapter
from src.mcp_adapters.base_adapter import MCPResult, MCPError


class TestSnykAdapter:
    """Tests for SnykAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return SnykAdapter(mock_mode=True)

    def test_supported_operations(self, adapter):
        """Test getting supported operations."""
        ops = adapter.get_supported_operations()

        assert "scan_deps" in ops
        assert "scan_container" in ops
        assert "lookup_vuln" in ops
        assert "search_vulns" in ops
        assert "get_vuln_details" in ops
        assert "list_cves" in ops

    def test_scan_dependencies(self, adapter):
        """Test dependency scan."""
        result = adapter.scan_dependencies()

        assert result.success is True
        assert "vulnerabilities" in result.data
        assert result.data["total_vulnerabilities"] > 0

    def test_scan_dependencies_has_severity_counts(self, adapter):
        """Test dependency scan includes severity counts."""
        result = adapter.scan_dependencies()

        assert result.success is True
        assert "critical" in result.data
        assert "high" in result.data
        assert "medium" in result.data
        assert "low" in result.data

    def test_scan_container(self, adapter):
        """Test container scan."""
        result = adapter.scan_container("nginx:latest")

        assert result.success is True
        assert result.data["image"] == "nginx:latest"
        assert "vulnerabilities" in result.data

    def test_lookup_vulnerability(self, adapter):
        """Test vulnerability lookup."""
        result = adapter.lookup_vulnerability("CVE-2021-44228")

        assert result.success is True
        assert result.data["id"] == "CVE-2021-44228"
        assert "severity" in result.data
        assert "cvss_score" in result.data

    def test_lookup_vulnerability_has_details(self, adapter):
        """Test vulnerability lookup includes details."""
        result = adapter.lookup_vulnerability("CVE-2021-44228")

        assert result.success is True
        assert "title" in result.data
        assert "description" in result.data
        assert "affected_packages" in result.data

    def test_search_vulnerabilities(self, adapter):
        """Test vulnerability search."""
        result = adapter.search_vulnerabilities("log4j", "2.14.1")

        assert result.success is True
        assert result.data["package"] == "log4j"
        assert "vulnerabilities" in result.data

    def test_get_vulnerability_details(self, adapter):
        """Test getting vulnerability details."""
        result = adapter.get_vulnerability_details("CVE-2021-44228")

        assert result.success is True
        assert "cvss_vector" in result.data
        assert "remediation" in result.data

    def test_vulnerability_details_has_exploit_info(self, adapter):
        """Test vulnerability details includes exploit info."""
        result = adapter.get_vulnerability_details("CVE-2021-44228")

        assert result.success is True
        assert "exploit_available" in result.data
        assert "exploit_details" in result.data

    def test_list_cves_for_package(self, adapter):
        """Test listing CVEs for a package."""
        result = adapter.list_cves_for_package("log4j", "2.14.1")

        assert result.success is True
        assert "cves" in result.data
        assert result.data["total"] > 0

    def test_cve_list_has_severity(self, adapter):
        """Test CVE list includes severity info."""
        result = adapter.list_cves_for_package("log4j")

        assert result.success is True
        for cve in result.data["cves"]:
            assert "cve_id" in cve
            assert "severity" in cve
            assert "cvss_score" in cve

    def test_result_to_evidence(self, adapter):
        """Test converting result to evidence format."""
        result = adapter.scan_dependencies()

        evidence = result.to_evidence()

        assert evidence["source"] == "snyk"
        assert evidence["source_type"] == "mcp_tool"
        assert "data" in evidence


class TestSnykAdapterEdgeCases:
    """Edge case tests for SnykAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return SnykAdapter(mock_mode=True)

    def test_unsupported_operation(self, adapter):
        """Test unsupported operation returns error result."""
        result = adapter.invoke("unsupported_operation", {})

        assert result.success is False
        assert "Unsupported operation" in result.error

    def test_scan_with_manifest_path(self, adapter):
        """Test scan with manifest path."""
        result = adapter.scan_dependencies(
            manifest_path="/path/to/package.json",
            project_type="npm",
        )

        assert result.success is True

    def test_search_without_version(self, adapter):
        """Test search without version filter."""
        result = adapter.search_vulnerabilities("axios")

        assert result.success is True
        assert result.data["package"] == "axios"
