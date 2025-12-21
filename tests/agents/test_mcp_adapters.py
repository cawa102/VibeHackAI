"""Tests for MCP adapters."""

from __future__ import annotations

import pytest

from src.mcp_adapters.base_adapter import BaseMCPAdapter, MCPResult, MCPError, MCPToolType
from src.mcp_adapters.shodan_adapter import ShodanAdapter
from src.mcp_adapters.osint_adapter import OSINTAdapter
from src.mcp_adapters.nmap_adapter import NmapAdapter


class TestMCPResult:
    """Tests for MCPResult."""

    def test_create_success_result(self):
        """Test creating successful result."""
        result = MCPResult(
            tool="shodan",
            operation="host_lookup",
            success=True,
            data={"ip": "192.168.1.1"},
        )

        assert result.success is True
        assert result.tool == "shodan"
        assert result.data["ip"] == "192.168.1.1"

    def test_create_error_result(self):
        """Test creating error result."""
        result = MCPResult(
            tool="nmap",
            operation="port_scan",
            success=False,
            error="Connection timeout",
        )

        assert result.success is False
        assert result.error == "Connection timeout"

    def test_to_dict(self):
        """Test converting to dict."""
        result = MCPResult(
            tool="osint",
            operation="whois",
            success=True,
            data={"domain": "example.com"},
        )

        d = result.to_dict()

        assert d["tool"] == "osint"
        assert d["operation"] == "whois"
        assert d["success"] is True

    def test_to_evidence(self):
        """Test converting to evidence format."""
        result = MCPResult(
            tool="shodan",
            operation="host_lookup",
            success=True,
            data={"ip": "10.0.0.1"},
        )

        evidence = result.to_evidence()

        assert evidence["source"] == "shodan"
        assert evidence["source_type"] == "mcp_tool"
        assert evidence["data"]["ip"] == "10.0.0.1"


class TestMCPError:
    """Tests for MCPError."""

    def test_create_error(self):
        """Test creating MCP error."""
        error = MCPError(
            message="Connection failed",
            tool="nmap",
            operation="port_scan",
            retryable=True,
        )

        assert str(error) == "Connection failed"
        assert error.tool == "nmap"
        assert error.retryable is True

    def test_error_to_dict(self):
        """Test converting error to dict."""
        error = MCPError(
            message="Timeout",
            tool="shodan",
            operation="search",
            details={"timeout": 30},
        )

        d = error.to_dict()

        assert d["error"] == "Timeout"
        assert d["details"]["timeout"] == 30


class TestShodanAdapter:
    """Tests for ShodanAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return ShodanAdapter(mock_mode=True)

    def test_supported_operations(self, adapter):
        """Test getting supported operations."""
        ops = adapter.get_supported_operations()

        assert "host_lookup" in ops
        assert "search" in ops
        assert "vulns" in ops

    def test_host_lookup(self, adapter):
        """Test host lookup."""
        result = adapter.host_lookup("192.168.1.1")

        assert result.success is True
        assert result.data["ip"] == "192.168.1.1"
        assert "ports" in result.data

    def test_search(self, adapter):
        """Test search."""
        result = adapter.search("nginx")

        assert result.success is True
        assert "matches" in result.data

    def test_dns_resolve(self, adapter):
        """Test DNS resolve."""
        result = adapter.dns_resolve(["example.com"])

        assert result.success is True
        assert "example.com" in result.data

    def test_reverse_dns(self, adapter):
        """Test reverse DNS."""
        result = adapter.reverse_dns(["192.168.1.1"])

        assert result.success is True
        assert "192.168.1.1" in result.data

    def test_get_ports(self, adapter):
        """Test getting ports."""
        result = adapter.get_ports("192.168.1.1")

        assert result.success is True
        assert "ports" in result.data

    def test_get_vulns(self, adapter):
        """Test getting vulnerabilities."""
        result = adapter.get_vulns("192.168.1.1")

        assert result.success is True
        assert "vulns" in result.data


class TestOSINTAdapter:
    """Tests for OSINTAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return OSINTAdapter(mock_mode=True)

    def test_supported_operations(self, adapter):
        """Test getting supported operations."""
        ops = adapter.get_supported_operations()

        assert "dns_lookup" in ops
        assert "whois" in ops
        assert "subdomains" in ops

    def test_dns_lookup(self, adapter):
        """Test DNS lookup."""
        result = adapter.dns_lookup("example.com", "A")

        assert result.success is True
        assert "records" in result.data

    def test_whois(self, adapter):
        """Test WHOIS lookup."""
        result = adapter.whois("example.com")

        assert result.success is True
        assert "registrar" in result.data

    def test_enumerate_subdomains(self, adapter):
        """Test subdomain enumeration."""
        result = adapter.enumerate_subdomains("example.com")

        assert result.success is True
        assert "subdomains" in result.data

    def test_mx_records(self, adapter):
        """Test MX records."""
        result = adapter.get_mx_records("example.com")

        assert result.success is True
        assert "mx_records" in result.data

    def test_ns_records(self, adapter):
        """Test NS records."""
        result = adapter.get_ns_records("example.com")

        assert result.success is True
        assert "ns_records" in result.data

    def test_txt_records(self, adapter):
        """Test TXT records."""
        result = adapter.get_txt_records("example.com")

        assert result.success is True
        assert "txt_records" in result.data

    def test_cert_search(self, adapter):
        """Test certificate search."""
        result = adapter.search_certificates("example.com")

        assert result.success is True
        assert "certificates" in result.data

    def test_email_harvest(self, adapter):
        """Test email harvesting."""
        result = adapter.harvest_emails("example.com")

        assert result.success is True
        assert "emails" in result.data

    def test_tech_detect(self, adapter):
        """Test technology detection."""
        result = adapter.detect_technologies("example.com")

        assert result.success is True
        assert "technologies" in result.data


class TestNmapAdapter:
    """Tests for NmapAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return NmapAdapter(mock_mode=True)

    def test_supported_operations(self, adapter):
        """Test getting supported operations."""
        ops = adapter.get_supported_operations()

        assert "port_scan" in ops
        assert "service_scan" in ops
        assert "os_detect" in ops

    def test_scan_profiles(self, adapter):
        """Test getting scan profiles."""
        profiles = adapter.get_scan_profiles()

        assert "quick" in profiles
        assert "stealth" in profiles
        assert "minimal" in profiles

    def test_port_scan(self, adapter):
        """Test port scan."""
        result = adapter.port_scan("192.168.1.1")

        assert result.success is True
        assert "ports" in result.data

    def test_service_scan(self, adapter):
        """Test service scan."""
        result = adapter.service_scan("192.168.1.1")

        assert result.success is True
        assert "ports" in result.data
        # Should have service info
        for port in result.data["ports"]:
            assert "service" in port or "product" in port

    def test_os_detect(self, adapter):
        """Test OS detection."""
        result = adapter.os_detect("192.168.1.1")

        assert result.success is True
        assert "os_matches" in result.data

    def test_script_scan(self, adapter):
        """Test NSE script scan."""
        result = adapter.script_scan("192.168.1.1")

        assert result.success is True
        assert "script_results" in result.data

    def test_quick_scan(self, adapter):
        """Test quick scan."""
        result = adapter.quick_scan("192.168.1.1")

        assert result.success is True
        assert "ports" in result.data

    def test_stealth_scan(self, adapter):
        """Test stealth scan."""
        result = adapter.stealth_scan("192.168.1.1")

        assert result.success is True
        assert result.data["scan_info"]["stealth"] is True

    def test_udp_scan(self, adapter):
        """Test UDP scan."""
        result = adapter.udp_scan("192.168.1.1")

        assert result.success is True
        assert all(p["protocol"] == "udp" for p in result.data["ports"])
