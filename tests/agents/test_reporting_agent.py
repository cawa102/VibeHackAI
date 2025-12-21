"""Tests for Reporting Agent."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

import pytest

from src.agents.reporting_agent import (
    ReportingAgent,
    Finding,
    ReportSection,
    PentestReport,
)
from src.agents.base_agent import AgentConfig, AgentContext, AgentType


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = Finding(
            finding_id="finding-001",
            title="SQL Injection",
            severity="high",
            description="SQL injection vulnerability found",
            impact="Database compromise",
            affected_component="login form",
            evidence_ids=["ev-001", "ev-002"],
            reproduction_steps=["Step 1", "Step 2"],
            remediation="Use parameterized queries",
        )

        assert finding.finding_id == "finding-001"
        assert finding.title == "SQL Injection"
        assert finding.severity == "high"
        assert finding.verified is True

    def test_finding_with_cve(self):
        """Test finding with CVE."""
        finding = Finding(
            finding_id="finding-002",
            title="Log4j RCE",
            severity="critical",
            description="Log4Shell vulnerability",
            impact="Remote code execution",
            affected_component="logging service",
            evidence_ids=["ev-003"],
            reproduction_steps=["Inject payload"],
            remediation="Update Log4j",
            cve_id="CVE-2021-44228",
            cvss_score=10.0,
        )

        assert finding.cve_id == "CVE-2021-44228"
        assert finding.cvss_score == 10.0

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = Finding(
            finding_id="finding-001",
            title="XSS",
            severity="medium",
            description="Cross-site scripting",
            impact="Session hijacking",
            affected_component="search form",
            evidence_ids=["ev-001"],
            reproduction_steps=["Enter script tag"],
            remediation="Escape output",
        )

        data = finding.to_dict()

        assert data["finding_id"] == "finding-001"
        assert data["title"] == "XSS"
        assert data["severity"] == "medium"
        assert "evidence_ids" in data


class TestReportSection:
    """Tests for ReportSection dataclass."""

    def test_section_creation(self):
        """Test creating a report section."""
        section = ReportSection(
            section_id="section-001",
            title="Introduction",
            content="This is the introduction.",
            order=1,
        )

        assert section.section_id == "section-001"
        assert section.title == "Introduction"
        assert section.order == 1
        assert section.subsections == []

    def test_section_with_subsections(self):
        """Test section with subsections."""
        subsection = ReportSection(
            section_id="section-001a",
            title="Subsection",
            content="Subsection content",
            order=1,
        )

        section = ReportSection(
            section_id="section-001",
            title="Main Section",
            content="Main content",
            order=1,
            subsections=[subsection],
        )

        assert len(section.subsections) == 1
        assert section.subsections[0].title == "Subsection"

    def test_section_to_dict(self):
        """Test section serialization."""
        section = ReportSection(
            section_id="section-001",
            title="Test Section",
            content="Test content",
            order=1,
        )

        data = section.to_dict()

        assert data["section_id"] == "section-001"
        assert data["title"] == "Test Section"
        assert data["subsections"] == []


class TestPentestReport:
    """Tests for PentestReport dataclass."""

    @pytest.fixture
    def sample_finding(self):
        """Create a sample finding."""
        return Finding(
            finding_id="finding-001",
            title="Test Vulnerability",
            severity="high",
            description="Test description",
            impact="Test impact",
            affected_component="test component",
            evidence_ids=["ev-001"],
            reproduction_steps=["Step 1"],
            remediation="Fix it",
        )

    @pytest.fixture
    def sample_report(self, sample_finding):
        """Create a sample report."""
        return PentestReport(
            report_id="report-001",
            title="Test Report",
            executive_summary="Test summary",
            scope={"targets": [{"type": "ip", "value": "192.168.1.1"}]},
            methodology="Test methodology",
            findings=[sample_finding],
            statistics={"total_findings": 1, "by_severity": {"high": 1}},
            recommendations=["Recommendation 1"],
            sections=[],
        )

    def test_report_creation(self, sample_report):
        """Test creating a report."""
        assert sample_report.report_id == "report-001"
        assert sample_report.title == "Test Report"
        assert len(sample_report.findings) == 1

    def test_report_to_dict(self, sample_report):
        """Test report serialization."""
        data = sample_report.to_dict()

        assert data["report_id"] == "report-001"
        assert "executive_summary" in data
        assert len(data["findings"]) == 1
        assert "generated_at" in data

    def test_report_to_json(self, sample_report):
        """Test JSON export."""
        json_str = sample_report.to_json()

        assert '"report_id": "report-001"' in json_str
        assert '"title": "Test Report"' in json_str

    def test_report_to_markdown(self, sample_report):
        """Test Markdown export."""
        md = sample_report.to_markdown()

        assert "# Test Report" in md
        assert "## Executive Summary" in md
        assert "Test summary" in md
        assert "## Findings" in md
        assert "Test Vulnerability" in md

    def test_markdown_includes_severity_table(self, sample_report):
        """Test Markdown includes severity statistics table."""
        md = sample_report.to_markdown()

        assert "| Severity | Count |" in md
        assert "| High | 1 |" in md

    def test_markdown_includes_scope(self, sample_report):
        """Test Markdown includes scope section."""
        md = sample_report.to_markdown()

        assert "## Scope" in md
        assert "192.168.1.1" in md


class TestReportingAgent:
    """Tests for ReportingAgent."""

    @pytest.fixture
    def agent(self):
        """Create agent in mock mode."""
        return ReportingAgent(mock_mode=True)

    @pytest.fixture
    def mock_bundle(self):
        """Create mock context bundle."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {
            "targets": [
                {"type": "ip", "value": "192.168.1.1"},
            ]
        }
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "SQL Injection",
                    "severity": "high",
                    "description": "SQL injection in login",
                    "impact": "Database access",
                    "affected_component": "login.php",
                    "evidence_ids": ["ev-001", "ev-002"],
                    "reproduction_steps": ["Enter ' OR 1=1 --"],
                    "remediation": "Use prepared statements",
                    "verified": True,
                },
                {
                    "finding_id": "fc-002",
                    "title": "XSS",
                    "severity": "medium",
                    "description": "Reflected XSS",
                    "impact": "Session hijacking",
                    "affected_component": "search.php",
                    "evidence_ids": ["ev-003"],
                    "reproduction_steps": ["Enter <script>alert(1)</script>"],
                    "remediation": "Encode output",
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None
        return bundle

    @pytest.fixture
    def mock_context(self, mock_bundle):
        """Create mock context."""
        config = AgentConfig(agent_type=AgentType.REPORTING)
        return AgentContext(bundle=mock_bundle, config=config)

    def test_agent_initialization(self, agent):
        """Test agent initializes correctly."""
        assert agent.agent_type == AgentType.REPORTING
        assert agent.mock_mode is True

    def test_run_with_findings(self, agent, mock_context):
        """Test running with findings."""
        output = agent.run(mock_context)

        assert output.success is True
        assert output.phase_result is not None
        assert output.phase_result["total_findings"] == 2
        assert output.phase_result["report_generated"] is True

    def test_findings_sorted_by_severity(self, agent, mock_context):
        """Test findings are sorted by severity."""
        agent.run(mock_context)

        report = agent.get_report()
        assert report is not None
        # High severity should come before medium
        assert report.findings[0].severity == "high"
        assert report.findings[1].severity == "medium"

    def test_run_without_findings(self, agent):
        """Test running without findings."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "empty-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": []}
        bundle.target_profile = {"finding_candidates": []}
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        assert output.phase_result["total_findings"] == 0

    def test_get_report(self, agent, mock_context):
        """Test getting report after run."""
        agent.run(mock_context)

        report = agent.get_report()

        assert report is not None
        assert report.report_id.startswith("report-")
        assert len(report.findings) == 2

    def test_export_json(self, agent, mock_context):
        """Test JSON export."""
        agent.run(mock_context)

        json_str = agent.export_json()

        assert json_str is not None
        assert "SQL Injection" in json_str
        assert "XSS" in json_str

    def test_export_markdown(self, agent, mock_context):
        """Test Markdown export."""
        agent.run(mock_context)

        md = agent.export_markdown()

        assert md is not None
        assert "# Penetration Testing Report" in md
        assert "SQL Injection" in md

    def test_export_before_run_returns_none(self, agent):
        """Test export before run returns None."""
        assert agent.export_json() is None
        assert agent.export_markdown() is None

    def test_statistics_calculation(self, agent, mock_context):
        """Test statistics are calculated correctly."""
        output = agent.run(mock_context)

        stats = output.phase_result["findings_by_severity"]
        assert stats.get("high") == 1
        assert stats.get("medium") == 1


class TestReportingAgentStatistics:
    """Tests for statistics calculation."""

    @pytest.fixture
    def agent(self):
        """Create agent in mock mode."""
        return ReportingAgent(mock_mode=True)

    def test_critical_risk_level(self, agent):
        """Test critical risk level is calculated."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "RCE",
                    "severity": "critical",
                    "description": "Remote code execution",
                    "impact": "Full compromise",
                    "affected_component": "api",
                    "evidence_ids": ["ev-001", "ev-002"],
                    "reproduction_steps": ["Send payload"],
                    "remediation": "Patch",
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        report = agent.get_report()

        assert report.statistics["risk_level"] == "Critical"

    def test_high_risk_level(self, agent):
        """Test high risk level is calculated."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "Auth Bypass",
                    "severity": "high",
                    "description": "Authentication bypass",
                    "impact": "Unauthorized access",
                    "affected_component": "auth",
                    "evidence_ids": ["ev-001", "ev-002"],
                    "reproduction_steps": ["Bypass login"],
                    "remediation": "Fix auth",
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        report = agent.get_report()

        assert report.statistics["risk_level"] == "High"


class TestReportingAgentRecommendations:
    """Tests for recommendation generation."""

    @pytest.fixture
    def agent(self):
        """Create agent in mock mode."""
        return ReportingAgent(mock_mode=True)

    def test_critical_recommendations(self, agent):
        """Test critical findings generate appropriate recommendations."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "RCE",
                    "severity": "critical",
                    "description": "Remote code execution",
                    "impact": "Full compromise",
                    "affected_component": "api",
                    "evidence_ids": ["ev-001", "ev-002"],
                    "reproduction_steps": ["Send payload"],
                    "remediation": "Patch",
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        report = agent.get_report()

        # Should have critical recommendation
        has_critical_rec = any(
            "CRITICAL" in rec for rec in report.recommendations
        )
        assert has_critical_rec is True

    def test_sql_injection_recommendations(self, agent):
        """Test SQL injection findings generate specific recommendations."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "SQL Injection",
                    "severity": "high",
                    "description": "SQL injection vulnerability",
                    "impact": "Database access",
                    "affected_component": "login",
                    "evidence_ids": ["ev-001", "ev-002"],
                    "reproduction_steps": ["Inject SQL"],
                    "remediation": "Parameterized queries",
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        report = agent.get_report()

        # Should have SQL injection specific recommendation
        has_sqli_rec = any(
            "parameterized" in rec.lower() for rec in report.recommendations
        )
        assert has_sqli_rec is True

    def test_cve_patch_recommendations(self, agent):
        """Test CVE findings generate patch recommendations."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "Log4Shell",
                    "severity": "critical",
                    "description": "Log4j vulnerability",
                    "impact": "RCE",
                    "affected_component": "logging",
                    "evidence_ids": ["ev-001", "ev-002"],
                    "reproduction_steps": ["Inject JNDI"],
                    "remediation": "Update Log4j",
                    "cve_id": "CVE-2021-44228",
                    "cvss_score": 10.0,
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        report = agent.get_report()

        # Should have patch recommendation
        has_patch_rec = any(
            "patch" in rec.lower() for rec in report.recommendations
        )
        assert has_patch_rec is True


class TestReportingAgentExecutiveSummary:
    """Tests for executive summary generation."""

    @pytest.fixture
    def agent(self):
        """Create agent in mock mode."""
        return ReportingAgent(mock_mode=True)

    def test_empty_summary_no_findings(self, agent):
        """Test summary when no findings."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {"finding_candidates": []}
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        report = agent.get_report()

        assert "No security vulnerabilities" in report.executive_summary

    def test_summary_includes_finding_count(self, agent):
        """Test summary includes finding count."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "Test",
                    "severity": "medium",
                    "description": "Test",
                    "impact": "Test",
                    "affected_component": "test",
                    "evidence_ids": ["ev-001"],
                    "reproduction_steps": ["Step"],
                    "remediation": "Fix",
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        report = agent.get_report()

        assert "1 security" in report.executive_summary

    def test_summary_highlights_critical(self, agent):
        """Test summary highlights critical vulnerabilities."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "Critical Vuln",
                    "severity": "critical",
                    "description": "Critical vulnerability",
                    "impact": "Full compromise",
                    "affected_component": "api",
                    "evidence_ids": ["ev-001"],
                    "reproduction_steps": ["Exploit"],
                    "remediation": "Fix",
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        report = agent.get_report()

        assert "Immediate attention" in report.executive_summary


class TestReportingAgentMarkdownOutput:
    """Tests for Markdown output formatting."""

    @pytest.fixture
    def agent(self):
        """Create agent in mock mode."""
        return ReportingAgent(mock_mode=True)

    def test_markdown_has_all_sections(self, agent):
        """Test Markdown has all required sections."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "10.0.0.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "Test Vuln",
                    "severity": "high",
                    "description": "Test description",
                    "impact": "Test impact",
                    "affected_component": "test",
                    "evidence_ids": ["ev-001", "ev-002"],
                    "reproduction_steps": ["Step 1", "Step 2"],
                    "remediation": "Fix it",
                    "cve_id": "CVE-2023-1234",
                    "cvss_score": 8.5,
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        md = agent.export_markdown()

        # Check all major sections
        assert "# Penetration Testing Report" in md
        assert "## Executive Summary" in md
        assert "## Summary Statistics" in md
        assert "## Scope" in md
        assert "## Methodology" in md
        assert "## Findings" in md
        assert "## Recommendations" in md

    def test_markdown_includes_cve_info(self, agent):
        """Test Markdown includes CVE information."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "CVE Test",
                    "severity": "critical",
                    "description": "Test",
                    "impact": "Test",
                    "affected_component": "test",
                    "evidence_ids": ["ev-001"],
                    "reproduction_steps": ["Step"],
                    "remediation": "Fix",
                    "cve_id": "CVE-2021-44228",
                    "cvss_score": 10.0,
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        agent.run(context)
        md = agent.export_markdown()

        assert "CVE-2021-44228" in md
        assert "10.0" in md


class TestReportingAgentPatchGeneration:
    """Tests for patch generation."""

    @pytest.fixture
    def agent(self):
        """Create agent in mock mode."""
        return ReportingAgent(mock_mode=True)

    def test_patch_contains_report(self, agent):
        """Test patch contains report data."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "Test",
                    "severity": "low",
                    "description": "Test",
                    "impact": "Test",
                    "affected_component": "test",
                    "evidence_ids": ["ev-001"],
                    "reproduction_steps": ["Step"],
                    "remediation": "Fix",
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.patch is not None
        # Patch should have operations for observations and report
        assert len(output.patch.operations) > 0

    def test_patch_has_observation_ops(self, agent):
        """Test patch has observation operations."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "finding_candidates": [
                {
                    "finding_id": "fc-001",
                    "title": "Test",
                    "severity": "medium",
                    "description": "Test",
                    "impact": "Test",
                    "affected_component": "test",
                    "evidence_ids": ["ev-001"],
                    "reproduction_steps": ["Step"],
                    "remediation": "Fix",
                    "verified": True,
                },
            ]
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        # Should have at least one observation about finding inclusion
        obs_ops = [
            op for op in output.patch.operations
            if op.target == "observations"
        ]
        assert len(obs_ops) >= 1


class TestReportingAgentSkipBehavior:
    """Tests for skip behavior."""

    @pytest.fixture
    def agent(self):
        """Create agent in mock mode."""
        return ReportingAgent(mock_mode=True)

    def test_skip_when_report_exists(self, agent):
        """Test skip when report already exists."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "report": {"report_id": "existing-report"},
            "finding_candidates": [],
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.REPORTING)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        # Should skip and return success with skipped flag in phase_result
        assert output.success is True
        assert output.phase_result is not None
        assert output.phase_result.get("skipped") is True
