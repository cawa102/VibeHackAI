"""Tests for Nmap Passer."""

from __future__ import annotations

import pytest

from src.passer.nmap_passer import NmapPasser
from src.passer.base import MCPType


class TestNmapPasser:
    """Tests for NmapPasser class."""

    @pytest.fixture
    def passer(self):
        """Create a NmapPasser instance."""
        return NmapPasser(
            session_id="test-session",
            scope_tag="test-scope",
            created_by="test",
        )

    def test_mcp_type(self, passer):
        """Test MCP type is correct."""
        assert passer.mcp_type == MCPType.NMAP

    def test_can_handle_xml(self, passer):
        """Test can_handle recognizes Nmap XML."""
        xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
        assert passer.can_handle(xml) is True

    def test_cannot_handle_random_data(self, passer):
        """Test can_handle rejects non-Nmap data."""
        assert passer.can_handle("random data") is False
        assert passer.can_handle({"random": "json"}) is False

    def test_normalize_simple_xml(self, passer):
        """Test normalizing simple Nmap XML."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" args="nmap -sV 192.168.1.1">
            <host>
                <status state="up"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <hostname name="test.local" type="PTR"/>
                <ports>
                    <port portid="22" protocol="tcp">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH" version="8.0"/>
                    </port>
                    <port portid="80" protocol="tcp">
                        <state state="open"/>
                        <service name="http" product="nginx" version="1.18"/>
                    </port>
                </ports>
            </host>
            <runstats>
                <finished exit="success"/>
                <hosts up="1" down="0" total="1"/>
            </runstats>
        </nmaprun>
        """
        result = passer.normalize(xml)

        assert result.success
        assert len(result.target_profiles) == 1
        assert len(result.observations) == 1

        target = result.target_profiles[0]
        assert target.ip_address == "192.168.1.1"
        assert len(target.ports) == 2
        assert target.ports[0].port == 22
        assert target.ports[0].service.name == "ssh"

    def test_normalize_with_os_detection(self, passer):
        """Test normalizing XML with OS detection."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap">
            <host>
                <status state="up"/>
                <address addr="10.0.0.1" addrtype="ipv4"/>
                <os>
                    <osmatch name="Linux 4.15" accuracy="95">
                        <osclass osfamily="Linux" vendor="Linux" osgen="4.X"/>
                    </osmatch>
                </os>
            </host>
            <runstats><finished exit="success"/></runstats>
        </nmaprun>
        """
        result = passer.normalize(xml)

        assert result.success
        assert len(result.target_profiles) == 1

        target = result.target_profiles[0]
        assert target.os_info is not None
        assert target.os_info.name == "Linux 4.15"
        assert target.os_info.family == "Linux"
        assert target.os_info.accuracy == 95

    def test_normalize_dict_format(self, passer):
        """Test normalizing dictionary format."""
        data = {
            "source": "nmap",
            "hosts": [
                {
                    "ip": "192.168.1.100",
                    "hostnames": ["server.local"],
                    "ports": [
                        {
                            "port": 443,
                            "protocol": "tcp",
                            "state": "open",
                            "service": {"name": "https", "product": "Apache"},
                        }
                    ],
                }
            ],
        }
        result = passer.normalize(data)

        assert result.success
        assert len(result.target_profiles) == 1

        target = result.target_profiles[0]
        assert target.ip_address == "192.168.1.100"
        assert "server.local" in target.hostnames
        assert len(target.ports) == 1
        assert target.ports[0].port == 443

    def test_normalize_bytes(self, passer):
        """Test normalizing bytes input."""
        xml = b'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/><address addr="1.2.3.4" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>'
        result = passer.normalize(xml)

        assert result.success
        assert len(result.target_profiles) == 1

    def test_normalize_invalid_xml(self, passer):
        """Test handling invalid XML."""
        result = passer.normalize("not valid xml")
        assert result.has_errors()

    def test_normalize_host_down(self, passer):
        """Test handling host that is down."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap">
            <host>
                <status state="down"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
            </host>
            <runstats><finished exit="success"/></runstats>
        </nmaprun>
        """
        result = passer.normalize(xml)

        # Should have warning about host being down
        assert result.has_warnings()
        # Should not create target for down host
        assert len(result.target_profiles) == 0

    def test_normalize_multiple_hosts(self, passer):
        """Test normalizing multiple hosts."""
        xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap">
            <host>
                <status state="up"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
            </host>
            <host>
                <status state="up"/>
                <address addr="192.168.1.2" addrtype="ipv4"/>
            </host>
            <runstats>
                <finished exit="success"/>
                <hosts up="2" total="2"/>
            </runstats>
        </nmaprun>
        """
        result = passer.normalize(xml)

        assert result.success
        assert len(result.target_profiles) == 2
