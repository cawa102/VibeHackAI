"""Tests for Snyk Passer."""

from __future__ import annotations

import json
import pytest

from src.passer.snyk_passer import SnykPasser
from src.passer.base import MCPType
from src.schemas.vuln_candidate import Severity


class TestSnykPasser:
    """Tests for SnykPasser class."""

    @pytest.fixture
    def passer(self):
        """Create a SnykPasser instance."""
        return SnykPasser(
            session_id="test-session",
            scope_tag="test-scope",
            created_by="test",
        )

    def test_mcp_type(self, passer):
        """Test MCP type is correct."""
        assert passer.mcp_type == MCPType.SNYK

    def test_can_handle_snyk_json(self, passer):
        """Test can_handle recognizes Snyk JSON."""
        data = {"vulnerabilities": [], "projectName": "test"}
        assert passer.can_handle(data) is True
        assert passer.can_handle(json.dumps(data)) is True

    def test_cannot_handle_random_data(self, passer):
        """Test can_handle rejects non-Snyk data."""
        assert passer.can_handle({"random": "data"}) is False

    def test_normalize_vulnerabilities(self, passer):
        """Test normalizing vulnerability list."""
        data = {
            "projectName": "my-project",
            "displayTargetFile": "package.json",
            "packageManager": "npm",
            "vulnerabilities": [
                {
                    "id": "SNYK-JS-LODASH-1234",
                    "title": "Prototype Pollution",
                    "severity": "high",
                    "packageName": "lodash",
                    "version": "4.17.15",
                    "description": "Prototype pollution vulnerability in lodash",
                    "identifiers": {
                        "CVE": ["CVE-2020-8203"],
                        "CWE": ["CWE-1321"],
                    },
                    "cvssScore": 7.4,
                    "isUpgradable": True,
                    "upgradePath": ["lodash@4.17.21"],
                },
                {
                    "id": "SNYK-JS-EXPRESS-5678",
                    "title": "Open Redirect",
                    "severity": "medium",
                    "packageName": "express",
                    "version": "4.17.0",
                    "cvssScore": 5.0,
                },
            ],
        }
        result = passer.normalize(data)

        assert result.success
        assert len(result.vuln_candidates) == 2
        assert len(result.observations) == 1

        # Check first vulnerability
        vuln1 = result.vuln_candidates[0]
        assert vuln1.title == "Prototype Pollution"
        assert vuln1.severity == Severity.HIGH
        assert vuln1.cve_id == "CVE-2020-8203"
        assert vuln1.cvss_score == 7.4
        assert vuln1.affected_component == "lodash@4.17.15"
        assert vuln1.metadata["is_upgradable"] is True

        # Check second vulnerability
        vuln2 = result.vuln_candidates[1]
        assert vuln2.severity == Severity.MEDIUM

    def test_normalize_critical_severity(self, passer):
        """Test critical severity mapping."""
        data = {
            "projectName": "test",
            "vulnerabilities": [
                {
                    "id": "SNYK-1",
                    "title": "RCE Vulnerability",
                    "severity": "critical",
                    "packageName": "dangerous",
                    "version": "1.0.0",
                    "cvssScore": 9.8,
                },
            ],
        }
        result = passer.normalize(data)

        assert result.success
        vuln = result.vuln_candidates[0]
        assert vuln.severity == Severity.CRITICAL

    def test_normalize_multiple_projects(self, passer):
        """Test normalizing multiple projects."""
        data = [
            {
                "projectName": "project-a",
                "vulnerabilities": [
                    {"id": "1", "title": "Vuln A", "severity": "low", "packageName": "a", "version": "1.0"},
                ],
            },
            {
                "projectName": "project-b",
                "vulnerabilities": [
                    {"id": "2", "title": "Vuln B", "severity": "high", "packageName": "b", "version": "2.0"},
                ],
            },
        ]
        result = passer.normalize(data)

        assert result.success
        assert len(result.vuln_candidates) == 2

    def test_observation_severity_counts(self, passer):
        """Test observation includes severity counts."""
        data = {
            "projectName": "test",
            "vulnerabilities": [
                {"id": "1", "title": "A", "severity": "critical", "packageName": "a", "version": "1"},
                {"id": "2", "title": "B", "severity": "high", "packageName": "b", "version": "1"},
                {"id": "3", "title": "C", "severity": "high", "packageName": "c", "version": "1"},
                {"id": "4", "title": "D", "severity": "medium", "packageName": "d", "version": "1"},
            ],
        }
        result = passer.normalize(data)

        obs = result.observations[0]
        assert "4 vulnerabilities" in obs.summary
        assert obs.metadata["severity_counts"]["critical"] == 1
        assert obs.metadata["severity_counts"]["high"] == 2
