"""Tests for Reconnaissance Agent."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from src.agents.reconnaissance_agent import ReconnaissanceAgent
from src.agents.base_agent import AgentConfig, AgentContext, AgentType
from src.mcp_adapters.shodan_adapter import ShodanAdapter
from src.mcp_adapters.osint_adapter import OSINTAdapter
from src.mcp_adapters.nmap_adapter import NmapAdapter


class TestReconnaissanceAgent:
    """Tests for ReconnaissanceAgent."""

    @pytest.fixture
    def agent(self):
        """Create reconnaissance agent with mock adapters."""
        return ReconnaissanceAgent(mock_mode=True)

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
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None
        return bundle

    @pytest.fixture
    def context(self, mock_bundle):
        """Create agent context."""
        config = AgentConfig(agent_type=AgentType.RECON)
        return AgentContext(bundle=mock_bundle, config=config)

    def test_initialization(self, agent):
        """Test agent initialization."""
        assert agent.agent_type == AgentType.RECON
        assert agent.shodan is not None
        assert agent.osint is not None
        assert agent.nmap is not None

    def test_run_with_ip_target(self, agent, context):
        """Test running with IP target."""
        output = agent.run(context)

        assert output.success is True
        assert output.patch is not None
        assert output.phase_result["targets_found"] >= 1

    def test_run_with_domain_target(self, agent, mock_bundle):
        """Test running with domain target."""
        mock_bundle.scope = {
            "targets": [
                {"type": "domain", "value": "example.com"},
            ]
        }
        config = AgentConfig(agent_type=AgentType.RECON)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        assert output.phase_result["targets_found"] >= 1

    def test_run_with_url_target(self, agent, mock_bundle):
        """Test running with URL target."""
        mock_bundle.scope = {
            "targets": [
                {"type": "url", "value": "https://example.com/app"},
            ]
        }
        config = AgentConfig(agent_type=AgentType.RECON)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True

    def test_run_with_cidr_target(self, agent, mock_bundle):
        """Test running with CIDR target."""
        mock_bundle.scope = {
            "targets": [
                {"type": "cidr", "value": "192.168.1.0/30"},  # Small CIDR
            ]
        }
        config = AgentConfig(agent_type=AgentType.RECON)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True

    def test_run_with_no_targets(self, agent, mock_bundle):
        """Test running with no targets."""
        mock_bundle.scope = {"targets": []}
        config = AgentConfig(agent_type=AgentType.RECON)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is False
        assert "No targets" in output.error

    def test_run_generates_patch(self, agent, context):
        """Test that run generates patch with operations."""
        output = agent.run(context)

        assert output.patch is not None
        assert len(output.patch.operations) > 0

    def test_run_collects_evidence(self, agent, context):
        """Test that run collects evidence."""
        output = agent.run(context)

        # Should have evidence operations
        evidence_ops = [
            op for op in output.patch.operations
            if op.op == "add_evidence"
        ]
        assert len(evidence_ops) > 0

    def test_run_records_observations(self, agent, context):
        """Test that run records observations."""
        output = agent.run(context)

        # Should have observation operations
        obs_ops = [
            op for op in output.patch.operations
            if op.op == "add_observation"
        ]
        assert len(obs_ops) > 0

    def test_run_records_decisions(self, agent, context):
        """Test that run records decision traces."""
        output = agent.run(context)

        assert len(output.decision_traces) > 0
        # Should have target selection decision
        decision_types = [d["decision_type"] for d in output.decision_traces]
        assert "target_selection" in decision_types

    def test_skip_with_existing_profile(self, agent, mock_bundle):
        """Test skipping when comprehensive profile exists."""
        mock_bundle.target_profile = {
            "ports": [22, 80, 443, 8080, 3306],
            "services": ["ssh", "http", "https", "mysql"],
        }
        config = AgentConfig(
            agent_type=AgentType.RECON,
            skip_on_sufficient_data=True,
        )
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        assert output.phase_result.get("skipped") is True


class TestReconnaissanceAgentIntegration:
    """Integration tests for ReconnaissanceAgent."""

    def test_full_ip_reconnaissance(self):
        """Test full IP reconnaissance workflow."""
        agent = ReconnaissanceAgent(mock_mode=True)

        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {
            "targets": [
                {"type": "ip", "value": "10.0.0.1"},
            ]
        }
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.RECON)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        assert output.patch is not None

        # Check operations
        op_types = [op.op for op in output.patch.operations]
        assert "add_evidence" in op_types
        assert "add_observation" in op_types

    def test_full_domain_reconnaissance(self):
        """Test full domain reconnaissance workflow."""
        agent = ReconnaissanceAgent(mock_mode=True)

        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {
            "targets": [
                {"type": "domain", "value": "testdomain.com"},
            ]
        }
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.RECON)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True

        # Should have many observations for domain
        obs_ops = [
            op for op in output.patch.operations
            if op.op == "add_observation"
        ]
        # Domain should generate: WHOIS, DNS records, subdomains, certs, tech detect
        assert len(obs_ops) >= 3

    def test_multiple_targets(self):
        """Test with multiple targets."""
        agent = ReconnaissanceAgent(mock_mode=True)

        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {
            "targets": [
                {"type": "ip", "value": "10.0.0.1"},
                {"type": "domain", "value": "example.com"},
            ]
        }
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.RECON)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        assert output.phase_result["targets_found"] == 2
