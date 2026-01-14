"""Tests for Enumeration Agent."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from src.agents.enumeration_agent import EnumerationAgent
from src.agents.base_agent import AgentConfig, AgentContext, AgentType
from src.mcp_adapters.burp_adapter import BurpAdapter


class TestEnumerationAgent:
    """Tests for EnumerationAgent."""

    @pytest.fixture
    def agent(self):
        """Create enumeration agent with mock adapters."""
        return EnumerationAgent(mock_mode=True)

    @pytest.fixture
    def mock_bundle(self):
        """Create mock context bundle."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {
            "targets": [
                {"type": "url", "value": "https://example.com"},
            ]
        }
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None
        return bundle

    @pytest.fixture
    def context(self, mock_bundle):
        """Create agent context."""
        config = AgentConfig(agent_type=AgentType.ENUMERATION)
        return AgentContext(bundle=mock_bundle, config=config)

    def test_initialization(self, agent):
        """Test agent initialization."""
        assert agent.agent_type == AgentType.ENUMERATION
        assert agent.burp is not None
        assert agent.nmap is not None

    def test_run_with_url_target(self, agent, context):
        """Test running with URL target."""
        output = agent.run(context)

        assert output.success is True
        assert output.patch is not None
        assert output.phase_result["targets_processed"] >= 1

    def test_run_with_domain_target(self, agent, mock_bundle):
        """Test running with domain target."""
        mock_bundle.scope = {
            "targets": [
                {"type": "domain", "value": "example.com"},
            ]
        }
        config = AgentConfig(agent_type=AgentType.ENUMERATION)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        # Domain should generate both http and https targets
        assert output.phase_result["targets_processed"] >= 1

    def test_run_with_target_profile(self, agent, mock_bundle):
        """Test running with existing target profile."""
        mock_bundle.scope = {"targets": []}
        mock_bundle.target_profile = {
            "targets": {
                "192.168.1.1": {
                    "ip": "192.168.1.1",
                    "ports": [80, 443],
                    "hostnames": ["example.com"],
                }
            }
        }
        config = AgentConfig(agent_type=AgentType.ENUMERATION)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True

    def test_run_with_no_web_targets(self, agent, mock_bundle):
        """Test running with no web targets."""
        mock_bundle.scope = {"targets": []}
        mock_bundle.target_profile = {}
        config = AgentConfig(agent_type=AgentType.ENUMERATION)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is False
        assert "No web targets" in output.error

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

    def test_run_finds_forms(self, agent, context):
        """Test that run finds forms."""
        output = agent.run(context)

        assert output.phase_result["forms_found"] > 0

    def test_run_finds_endpoints(self, agent, context):
        """Test that run finds API endpoints."""
        output = agent.run(context)

        assert output.phase_result["endpoints_found"] > 0

    def test_run_finds_login_forms(self, agent, context):
        """Test that run finds login forms."""
        output = agent.run(context)

        assert output.phase_result["login_forms_found"] > 0

    def test_run_finds_file_uploads(self, agent, context):
        """Test that run finds file upload points."""
        output = agent.run(context)

        assert output.phase_result["file_uploads_found"] > 0

    def test_run_detects_auth_mechanisms(self, agent, context):
        """Test that run detects authentication mechanisms."""
        output = agent.run(context)

        assert len(output.phase_result["auth_mechanisms_detected"]) > 0

    def test_run_records_decisions(self, agent, context):
        """Test that run records decision traces."""
        output = agent.run(context)

        assert len(output.decision_traces) > 0
        decision_types = [d["decision_type"] for d in output.decision_traces]
        assert "target_selection" in decision_types

    def test_skip_with_existing_enumeration(self, agent, mock_bundle):
        """Test skipping when comprehensive enumeration exists."""
        mock_bundle.target_profile = {
            "input_points": [{"id": f"ip-{i}"} for i in range(10)],
            "endpoints": [{"id": f"ep-{i}"} for i in range(5)],
            "auth_info": {"mechanisms": ["form_based"]},
        }
        config = AgentConfig(
            agent_type=AgentType.ENUMERATION,
            skip_on_sufficient_data=True,
        )
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        assert output.phase_result.get("skipped") is True


class TestEnumerationAgentIntegration:
    """Integration tests for EnumerationAgent."""

    def test_full_web_enumeration(self):
        """Test full web enumeration workflow."""
        agent = EnumerationAgent(mock_mode=True)

        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {
            "targets": [
                {"type": "url", "value": "https://webapp.example.com"},
            ]
        }
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.ENUMERATION)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        assert output.patch is not None

        # Check operations
        op_types = [op.op for op in output.patch.operations]
        assert "add_evidence" in op_types
        assert "add_observation" in op_types
        assert "update_target_profile" in op_types

    def test_enumeration_from_recon_results(self):
        """Test enumeration using recon phase results."""
        agent = EnumerationAgent(mock_mode=True)

        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 2  # After recon
        bundle.scope = {"targets": []}
        bundle.target_profile = {
            "targets": {
                "10.0.0.1": {
                    "ip": "10.0.0.1",
                    "ports": [80, 443, 8080],
                    "hostnames": ["api.example.com", "www.example.com"],
                }
            }
        }
        bundle.observations = [
            {"type": "host_discovery", "data": {"ip": "10.0.0.1"}},
        ]
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.ENUMERATION)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        # Should have processed multiple web targets
        assert output.phase_result["targets_processed"] >= 1

    def test_multiple_web_targets(self):
        """Test with multiple web targets."""
        agent = EnumerationAgent(mock_mode=True)

        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {
            "targets": [
                {"type": "url", "value": "https://app1.example.com"},
                {"type": "url", "value": "https://app2.example.com"},
                {"type": "domain", "value": "app3.example.com"},
            ]
        }
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.ENUMERATION)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        # Should have processed all targets
        assert output.phase_result["targets_processed"] >= 3


class TestEnumerationAgentInputPointAnalysis:
    """Tests for input point analysis."""

    @pytest.fixture
    def agent(self):
        """Create enumeration agent with mock adapters."""
        return EnumerationAgent(mock_mode=True)

    @pytest.fixture
    def context(self):
        """Create agent context."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {
            "targets": [
                {"type": "url", "value": "https://example.com"},
            ]
        }
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None
        config = AgentConfig(agent_type=AgentType.ENUMERATION)
        return AgentContext(bundle=bundle, config=config)

    def test_form_fields_captured(self, agent, context):
        """Test that form fields are captured."""
        output = agent.run(context)

        # Find update_target_profile operation
        profile_ops = [
            op for op in output.patch.operations
            if op.op == "update_target_profile"
        ]
        assert len(profile_ops) > 0

        payload = profile_ops[0].payload
        input_points = payload.get("input_points", [])
        forms = [ip for ip in input_points if ip.get("type") == "form"]

        assert len(forms) > 0
        # Forms should have fields
        for form in forms:
            assert "fields" in form

    def test_api_parameters_captured(self, agent, context):
        """Test that API parameters are captured."""
        output = agent.run(context)

        profile_ops = [
            op for op in output.patch.operations
            if op.op == "update_target_profile"
        ]
        assert len(profile_ops) > 0

        payload = profile_ops[0].payload
        input_points = payload.get("input_points", [])
        apis = [ip for ip in input_points if ip.get("type") == "api"]

        assert len(apis) > 0
        # APIs should have parameters
        for api in apis:
            assert "parameters" in api


class TestEnumerationAgentAuthAnalysis:
    """Tests for authentication analysis."""

    @pytest.fixture
    def agent(self):
        """Create enumeration agent with mock adapters."""
        return EnumerationAgent(mock_mode=True)

    @pytest.fixture
    def context(self):
        """Create agent context."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {
            "targets": [
                {"type": "url", "value": "https://example.com"},
            ]
        }
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None
        config = AgentConfig(agent_type=AgentType.ENUMERATION)
        return AgentContext(bundle=bundle, config=config)

    def test_auth_info_captured(self, agent, context):
        """Test that auth info is captured."""
        output = agent.run(context)

        profile_ops = [
            op for op in output.patch.operations
            if op.op == "update_target_profile"
        ]
        assert len(profile_ops) > 0

        payload = profile_ops[0].payload
        auth_info = payload.get("auth_info", {})

        assert "mechanisms" in auth_info
        assert len(auth_info["mechanisms"]) > 0

    def test_login_forms_identified(self, agent, context):
        """Test that login forms are identified."""
        output = agent.run(context)

        profile_ops = [
            op for op in output.patch.operations
            if op.op == "update_target_profile"
        ]
        payload = profile_ops[0].payload
        auth_info = payload.get("auth_info", {})

        # Should have form_based auth detected
        assert "form_based" in auth_info.get("mechanisms", [])

    def test_session_management_detected(self, agent, context):
        """Test that session management is detected."""
        output = agent.run(context)

        profile_ops = [
            op for op in output.patch.operations
            if op.op == "update_target_profile"
        ]
        payload = profile_ops[0].payload
        auth_info = payload.get("auth_info", {})

        # Should have session_cookie auth detected
        assert "session_cookie" in auth_info.get("mechanisms", [])
