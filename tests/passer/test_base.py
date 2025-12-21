"""Tests for the base Passer classes."""

from __future__ import annotations

import pytest

from src.passer.base import (
    BasePasser,
    MCPType,
    PasserError,
    PasserResult,
    PasserRegistry,
    normalize,
)


class TestPasserResult:
    """Tests for PasserResult class."""

    def test_create_empty_result(self):
        """Test creating an empty result."""
        result = PasserResult()
        assert result.success is True
        assert len(result.target_profiles) == 0
        assert len(result.observations) == 0
        assert len(result.warnings) == 0
        assert len(result.errors) == 0

    def test_add_warning(self):
        """Test adding warnings."""
        result = PasserResult()
        result.add_warning("Test warning")
        assert result.has_warnings()
        assert "Test warning" in result.warnings

    def test_add_error(self):
        """Test adding errors sets success to False."""
        result = PasserResult()
        result.add_error("Test error")
        assert result.has_errors()
        assert result.success is False
        assert "Test error" in result.errors

    def test_merge_results(self):
        """Test merging two results."""
        result1 = PasserResult()
        result1.add_warning("Warning 1")

        result2 = PasserResult()
        result2.add_warning("Warning 2")
        result2.add_error("Error 1")

        result1.merge(result2)

        assert len(result1.warnings) == 2
        assert len(result1.errors) == 1
        assert result1.success is False

    def test_to_dict(self):
        """Test converting to dictionary."""
        result = PasserResult()
        result.add_warning("Test warning")

        d = result.to_dict()

        assert "success" in d
        assert "warnings" in d
        assert "errors" in d
        assert d["success"] is True
        assert "Test warning" in d["warnings"]


class TestPasserError:
    """Tests for PasserError exception."""

    def test_create_error(self):
        """Test creating an error."""
        error = PasserError("Test error", MCPType.NMAP)
        assert str(error) == "Test error"
        assert error.mcp_type == MCPType.NMAP

    def test_error_with_partial_result(self):
        """Test error with partial result."""
        partial = {"some": "data"}
        error = PasserError("Error", partial_result=partial)
        assert error.partial_result == partial


class TestPasserRegistry:
    """Tests for PasserRegistry."""

    def test_registry_has_passers(self):
        """Test that passers are registered."""
        passers = PasserRegistry.get_all()
        assert len(passers) > 0

    def test_get_nmap_passer(self):
        """Test getting Nmap passer."""
        passer_class = PasserRegistry.get(MCPType.NMAP)
        assert passer_class is not None
        assert passer_class.mcp_type == MCPType.NMAP

    def test_get_shodan_passer(self):
        """Test getting Shodan passer."""
        passer_class = PasserRegistry.get(MCPType.SHODAN)
        assert passer_class is not None

    def test_get_unknown_passer(self):
        """Test getting unknown passer returns None."""
        passer_class = PasserRegistry.get(MCPType.UNKNOWN)
        assert passer_class is None


class TestNormalize:
    """Tests for the normalize function."""

    def test_normalize_with_unknown_type(self):
        """Test normalizing with unknown type."""
        result = normalize(
            raw_output={"unknown": "data"},
            mcp_type=None,
            session_id="test-session",
            scope_tag="test-scope",
        )
        # Should fail to detect type
        assert result.has_errors()

    def test_normalize_with_nmap_xml(self):
        """Test normalizing Nmap XML."""
        nmap_xml = """<?xml version="1.0"?>
        <nmaprun scanner="nmap" args="nmap -sV 192.168.1.1">
            <host>
                <status state="up"/>
                <address addr="192.168.1.1" addrtype="ipv4"/>
                <ports>
                    <port portid="80" protocol="tcp">
                        <state state="open"/>
                        <service name="http" product="nginx" version="1.18"/>
                    </port>
                </ports>
            </host>
            <runstats>
                <finished exit="success"/>
            </runstats>
        </nmaprun>
        """
        result = normalize(
            raw_output=nmap_xml,
            mcp_type=MCPType.NMAP,
            session_id="test-session",
            scope_tag="test-scope",
        )
        assert result.success
        assert len(result.target_profiles) >= 1

    def test_normalize_with_invalid_mcp_type(self):
        """Test normalizing with invalid MCP type."""
        result = normalize(
            raw_output="some data",
            mcp_type=MCPType.UNKNOWN,
            session_id="test-session",
            scope_tag="test-scope",
        )
        # Should fail - no passer registered for UNKNOWN
        assert result.has_errors()
