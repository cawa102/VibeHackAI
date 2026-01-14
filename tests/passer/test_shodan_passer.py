"""Tests for Shodan Passer."""

from __future__ import annotations

import json
import pytest

from src.passer.shodan_passer import ShodanPasser
from src.passer.base import MCPType


class TestShodanPasser:
    """Tests for ShodanPasser class."""

    @pytest.fixture
    def passer(self):
        """Create a ShodanPasser instance."""
        return ShodanPasser(
            session_id="test-session",
            scope_tag="test-scope",
            created_by="test",
        )

    def test_mcp_type(self, passer):
        """Test MCP type is correct."""
        assert passer.mcp_type == MCPType.SHODAN

    def test_can_handle_shodan_json(self, passer):
        """Test can_handle recognizes Shodan JSON."""
        data = {"ip_str": "1.2.3.4", "ports": [80, 443]}
        assert passer.can_handle(data) is True
        assert passer.can_handle(json.dumps(data)) is True

    def test_cannot_handle_random_data(self, passer):
        """Test can_handle rejects non-Shodan data."""
        assert passer.can_handle({"random": "data"}) is False
        assert passer.can_handle("random string") is False

    def test_normalize_host_lookup(self, passer):
        """Test normalizing single host lookup."""
        data = {
            "ip_str": "8.8.8.8",
            "hostnames": ["dns.google"],
            "ports": [53, 443],
            "os": "Linux",
            "org": "Google LLC",
            "isp": "Google",
            "asn": "AS15169",
            "country_code": "US",
            "data": [
                {
                    "port": 53,
                    "transport": "udp",
                    "product": "Google DNS",
                    "data": "DNS server",
                    "_shodan": {"module": "dns"},
                },
                {
                    "port": 443,
                    "transport": "tcp",
                    "product": "nginx",
                    "data": "HTTP/1.1 200 OK",
                    "_shodan": {"module": "https"},
                },
            ],
        }
        result = passer.normalize(data)

        assert result.success
        assert len(result.target_profiles) == 1
        assert len(result.observations) == 1

        target = result.target_profiles[0]
        assert target.ip_address == "8.8.8.8"
        assert "dns.google" in target.hostnames
        assert len(target.ports) == 2
        assert target.os_info.name == "Linux"
        assert target.metadata["org"] == "Google LLC"

    def test_normalize_search_results(self, passer):
        """Test normalizing search results."""
        data = {
            "query": "nginx",
            "total": 1000,
            "matches": [
                {
                    "ip_str": "10.0.0.1",
                    "ports": [80],
                    "hostnames": ["web1.example.com"],
                },
                {
                    "ip_str": "10.0.0.2",
                    "ports": [80, 443],
                    "hostnames": ["web2.example.com"],
                },
            ],
        }
        result = passer.normalize(data)

        assert result.success
        assert len(result.target_profiles) == 2
        assert len(result.observations) == 1

        obs = result.observations[0]
        assert "search" in obs.action
        assert obs.metadata["total_results"] == 1000

    def test_normalize_json_string(self, passer):
        """Test normalizing JSON string input."""
        data = {"ip_str": "192.168.1.1", "ports": [22]}
        result = passer.normalize(json.dumps(data))

        assert result.success
        assert len(result.target_profiles) == 1

    def test_normalize_with_tech_stack(self, passer):
        """Test technology stack extraction."""
        data = {
            "ip_str": "10.0.0.1",
            "tags": ["web", "ssl"],
            "data": [
                {
                    "port": 443,
                    "product": "Apache",
                    "ssl": {"cert": {"issued": "2024-01-01"}},
                    "http": {"server": "Apache/2.4.41"},
                    "_shodan": {"module": "https"},
                },
            ],
        }
        result = passer.normalize(data)

        assert result.success
        target = result.target_profiles[0]
        assert "web" in target.tech_stack
        assert "TLS" in target.tech_stack
        assert "Apache" in target.tech_stack

    def test_normalize_missing_ip(self, passer):
        """Test handling data without IP address."""
        data = {"ports": [80, 443]}  # Missing ip_str
        result = passer.normalize(data)

        # Should have warning about missing IP
        assert result.has_warnings() or len(result.target_profiles) == 0

    def test_normalize_bytes_input(self, passer):
        """Test normalizing bytes input."""
        data = b'{"ip_str": "1.2.3.4", "ports": [80]}'
        result = passer.normalize(data)

        assert result.success
        assert len(result.target_profiles) == 1
