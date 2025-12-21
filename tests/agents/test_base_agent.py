"""Tests for base agent."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from datetime import datetime

from src.agents.base_agent import (
    BaseAgent,
    AgentConfig,
    AgentContext,
    AgentOutput,
    AgentType,
    AgentStatus,
    DecisionTrace,
)


class ConcreteAgent(BaseAgent):
    """Concrete implementation for testing."""

    def _execute(self, context):
        patch = self._create_patch(context, [])
        return self._create_success_output(
            context,
            patch,
            {"test_result": True},
        )


class FailingAgent(BaseAgent):
    """Agent that always fails."""

    def _execute(self, context):
        return self._create_error_output(context, "Test failure")


class TestAgentConfig:
    """Tests for AgentConfig."""

    def test_create_config(self):
        """Test creating config."""
        config = AgentConfig(agent_type=AgentType.RECON)

        assert config.agent_type == AgentType.RECON
        assert config.timeout_seconds == 600
        assert config.max_retries == 2

    def test_config_custom_values(self):
        """Test config with custom values."""
        config = AgentConfig(
            agent_type=AgentType.ENUMERATION,
            timeout_seconds=300,
            max_retries=5,
            verbose=True,
        )

        assert config.timeout_seconds == 300
        assert config.max_retries == 5
        assert config.verbose is True


class TestAgentContext:
    """Tests for AgentContext."""

    @pytest.fixture
    def mock_bundle(self):
        """Create mock context bundle."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": []}
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None
        return bundle

    def test_create_context(self, mock_bundle):
        """Test creating context."""
        config = AgentConfig(agent_type=AgentType.RECON)
        context = AgentContext(bundle=mock_bundle, config=config)

        assert context.session_id == "test-session"
        assert context.scope_tag == "test-scope"
        assert context.run_id.startswith("run-")

    def test_context_properties(self, mock_bundle):
        """Test context property access."""
        config = AgentConfig(agent_type=AgentType.RECON)
        context = AgentContext(bundle=mock_bundle, config=config)

        assert context.state_version == 1
        assert context.scope == {"targets": []}
        assert context.observations == []


class TestAgentOutput:
    """Tests for AgentOutput."""

    def test_create_success_output(self):
        """Test creating successful output."""
        output = AgentOutput(
            agent_type="recon_agent",
            run_id="run-123",
            success=True,
            phase_result={"findings": 5},
        )

        assert output.success is True
        assert output.error is None

    def test_create_error_output(self):
        """Test creating error output."""
        output = AgentOutput(
            agent_type="recon_agent",
            run_id="run-123",
            success=False,
            error="Something went wrong",
        )

        assert output.success is False
        assert output.error == "Something went wrong"

    def test_output_to_dict(self):
        """Test converting output to dict."""
        output = AgentOutput(
            agent_type="recon_agent",
            run_id="run-123",
            success=True,
            duration_ms=1500,
        )

        result = output.to_dict()

        assert result["agent_type"] == "recon_agent"
        assert result["success"] is True
        assert result["duration_ms"] == 1500


class TestDecisionTrace:
    """Tests for DecisionTrace."""

    def test_create_decision(self):
        """Test creating decision trace."""
        decision = DecisionTrace(
            decision_id="dec-001",
            decision_type="skip",
            description="Skipping Nmap",
            reasoning="Sufficient passive data",
        )

        assert decision.decision_type == "skip"
        assert decision.description == "Skipping Nmap"

    def test_decision_to_dict(self):
        """Test converting decision to dict."""
        decision = DecisionTrace(
            decision_id="dec-001",
            decision_type="target_selection",
            description="Selected 3 targets",
            reasoning="Within scope",
            inputs={"targets": 3},
        )

        result = decision.to_dict()

        assert result["decision_id"] == "dec-001"
        assert result["inputs"]["targets"] == 3


class TestBaseAgent:
    """Tests for BaseAgent."""

    @pytest.fixture
    def config(self):
        """Create agent config."""
        return AgentConfig(agent_type=AgentType.RECON)

    @pytest.fixture
    def agent(self, config):
        """Create concrete agent."""
        return ConcreteAgent(config)

    @pytest.fixture
    def mock_bundle(self):
        """Create mock bundle."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {}
        bundle.observations = []
        bundle.instructions = None
        return bundle

    def test_initial_status(self, agent):
        """Test initial status is IDLE."""
        assert agent.status == AgentStatus.IDLE

    def test_agent_type(self, agent):
        """Test agent type property."""
        assert agent.agent_type == AgentType.RECON

    def test_run_success(self, agent, config, mock_bundle):
        """Test successful agent run."""
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        assert agent.status == AgentStatus.COMPLETED

    def test_run_failure(self, config, mock_bundle):
        """Test failed agent run."""
        agent = FailingAgent(config)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is False
        assert agent.status == AgentStatus.FAILED

    def test_run_no_scope(self, agent, config, mock_bundle):
        """Test run with no scope."""
        mock_bundle.scope = None
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is False
        assert "No scope" in output.error

    def test_stop(self, agent):
        """Test stopping agent."""
        agent.stop()

        assert agent.status == AgentStatus.STOPPED

    def test_duration_recorded(self, agent, config, mock_bundle):
        """Test duration is recorded."""
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.duration_ms is not None
        assert output.duration_ms >= 0

    def test_decision_traces_recorded(self, config, mock_bundle):
        """Test decision traces are recorded."""

        class DecisionAgent(BaseAgent):
            def _execute(self, context):
                self._record_decision(
                    "test_decision",
                    "Test description",
                    "Test reasoning",
                )
                patch = self._create_patch(context, [])
                return self._create_success_output(context, patch, {})

        agent = DecisionAgent(config)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert len(output.decision_traces) == 1
        assert output.decision_traces[0]["decision_type"] == "test_decision"

    def test_warnings_recorded(self, config, mock_bundle):
        """Test warnings are recorded."""

        class WarningAgent(BaseAgent):
            def _execute(self, context):
                self._add_warning("Test warning")
                patch = self._create_patch(context, [])
                return self._create_success_output(context, patch, {})

        agent = WarningAgent(config)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert "Test warning" in output.warnings
