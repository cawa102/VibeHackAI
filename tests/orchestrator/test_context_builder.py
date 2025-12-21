"""Tests for context builder."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from src.orchestrator.context_builder import (
    ContextBuilder,
    ContextBundle,
    AGENT_CONTEXT_REQUIREMENTS,
)
from src.orchestrator.router import Phase


class TestContextBundle:
    """Tests for ContextBundle dataclass."""

    def test_create_bundle(self):
        """Test creating a context bundle."""
        bundle = ContextBundle(
            session_id="test-session",
            scope_tag="test-scope",
            agent_type="recon_agent",
            phase="recon",
            state_version=1,
        )

        assert bundle.session_id == "test-session"
        assert bundle.scope_tag == "test-scope"
        assert bundle.agent_type == "recon_agent"
        assert bundle.phase == "recon"
        assert bundle.state_version == 1

    def test_bundle_to_dict(self):
        """Test converting bundle to dict."""
        bundle = ContextBundle(
            session_id="test-session",
            scope_tag="test-scope",
            agent_type="recon_agent",
            phase="recon",
            state_version=1,
            scope={"targets": ["192.168.1.1"]},
        )

        result = bundle.to_dict()

        assert result["session_id"] == "test-session"
        assert result["scope_tag"] == "test-scope"
        assert result["agent_type"] == "recon_agent"
        assert result["phase"] == "recon"
        assert result["scope"]["targets"] == ["192.168.1.1"]

    def test_bundle_defaults(self):
        """Test bundle default values."""
        bundle = ContextBundle(
            session_id="test",
            scope_tag="test",
            agent_type="test",
            phase="init",
            state_version=1,
        )

        assert bundle.scope is None
        assert bundle.target_profile is None
        assert bundle.observations == []
        assert bundle.vuln_candidates == []
        assert bundle.exploit_candidates == []
        assert bundle.previous_phase_result is None
        assert bundle.execution_plans == []
        assert bundle.execution_results == []
        assert bundle.instructions is None

    def test_bundle_from_dict(self):
        """Test creating bundle from dict."""
        data = {
            "session_id": "test",
            "scope_tag": "scope",
            "agent_type": "recon_agent",
            "phase": "recon",
            "state_version": 5,
            "scope": {"targets": []},
            "created_at": "2024-01-01T12:00:00Z",
        }

        bundle = ContextBundle.from_dict(data)

        assert bundle.session_id == "test"
        assert bundle.state_version == 5
        assert bundle.scope == {"targets": []}


class TestAgentContextRequirements:
    """Tests for agent context requirements."""

    def test_recon_agent_requirements(self):
        """Test recon agent requirements."""
        reqs = AGENT_CONTEXT_REQUIREMENTS.get("recon_agent", {})
        include = reqs.get("include", [])
        assert "scope" in include
        assert "target_profile" in include

    def test_enumeration_agent_requirements(self):
        """Test enumeration agent requirements."""
        reqs = AGENT_CONTEXT_REQUIREMENTS.get("enumeration_agent", {})
        include = reqs.get("include", [])
        assert "scope" in include
        assert "observations" in include

    def test_planner_agent_requirements(self):
        """Test planner agent requirements."""
        reqs = AGENT_CONTEXT_REQUIREMENTS.get("planner_agent", {})
        include = reqs.get("include", [])
        assert "scope" in include
        assert "target_profile" in include
        assert "vuln_candidates" in include
        assert "exploit_candidates" in include

    def test_exploitation_agent_requirements(self):
        """Test exploitation agent requirements."""
        reqs = AGENT_CONTEXT_REQUIREMENTS.get("exploitation_agent", {})
        include = reqs.get("include", [])
        assert "scope" in include
        assert "execution_plans" in include

    def test_reporting_agent_requirements(self):
        """Test reporting agent requirements."""
        reqs = AGENT_CONTEXT_REQUIREMENTS.get("reporting_agent", {})
        include = reqs.get("include", [])
        assert "scope" in include
        assert "vuln_candidates" in include
        assert "execution_results" in include


class TestContextBuilder:
    """Tests for ContextBuilder class."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.read_json.return_value = {}
        store.read_jsonl.return_value = []
        store.exists.return_value = False
        store.get_version.return_value = 1
        return store

    @pytest.fixture
    def mock_evidence_ledger(self):
        """Create mock evidence ledger."""
        ledger = MagicMock()
        ledger.query.return_value = []
        return ledger

    @pytest.fixture
    def builder(self, mock_state_store, mock_evidence_ledger):
        """Create context builder."""
        return ContextBuilder(
            mock_state_store,
            mock_evidence_ledger,
            session_id="test-session",
            scope_tag="test-scope",
        )

    def test_build_basic_bundle(self, builder):
        """Test building a basic context bundle."""
        bundle = builder.build(
            agent_type="recon_agent",
            phase=Phase.RECON,
        )

        assert bundle.session_id == "test-session"
        assert bundle.scope_tag == "test-scope"
        assert bundle.agent_type == "recon_agent"
        assert bundle.phase == "recon"

    def test_build_with_instructions(self, builder):
        """Test building bundle with instructions."""
        bundle = builder.build(
            agent_type="recon_agent",
            phase=Phase.RECON,
            instructions="Focus on web services",
        )

        assert bundle.instructions == "Focus on web services"

    def test_build_with_previous_result(self, builder):
        """Test building bundle with previous phase result."""
        previous = {"findings": ["found something"]}
        bundle = builder.build(
            agent_type="enumeration_agent",
            phase=Phase.ENUMERATION,
            previous_result=previous,
        )

        assert bundle.previous_phase_result == previous

    def test_build_loads_scope(self, builder, mock_state_store):
        """Test builder loads scope when required."""
        mock_state_store.read_json.return_value = {
            "targets": [{"value": "192.168.1.1", "type": "ip"}]
        }

        bundle = builder.build(
            agent_type="recon_agent",
            phase=Phase.RECON,
        )

        assert bundle.scope is not None
        mock_state_store.read_json.assert_called()

    def test_build_loads_observations(self, builder, mock_state_store):
        """Test builder loads observations when required."""
        mock_state_store.read_jsonl.return_value = [
            {"type": "port_open", "port": 80}
        ]

        bundle = builder.build(
            agent_type="enumeration_agent",
            phase=Phase.ENUMERATION,
        )

        # Observations should be loaded for enumeration agent
        assert bundle.observations == [{"type": "port_open", "port": 80}]

    def test_build_loads_vulns(self, builder, mock_state_store):
        """Test builder loads vulns when required."""
        mock_state_store.read_jsonl.return_value = [
            {"cve": "CVE-2024-1234", "severity": "high"}
        ]

        bundle = builder.build(
            agent_type="planner_agent",
            phase=Phase.PLANNER,
        )

        # Vulns should be loaded for planner agent
        assert bundle.vuln_candidates == [{"cve": "CVE-2024-1234", "severity": "high"}]

    def test_build_for_unknown_agent(self, builder):
        """Test building bundle for unknown agent type."""
        bundle = builder.build(
            agent_type="unknown_agent",
            phase=Phase.RECON,
        )

        # Should still work, falls back to recon_agent requirements
        assert bundle.agent_type == "unknown_agent"

    def test_build_handles_missing_files(self, builder, mock_state_store):
        """Test builder handles missing state files gracefully."""
        mock_state_store.read_json.side_effect = FileNotFoundError()
        mock_state_store.read_jsonl.return_value = []

        # Should not raise
        bundle = builder.build(
            agent_type="recon_agent",
            phase=Phase.RECON,
        )

        assert bundle is not None
        assert bundle.scope is None

    def test_get_minimal_bundle(self, builder, mock_state_store):
        """Test getting minimal bundle."""
        mock_state_store.read_json.return_value = {"targets": []}

        bundle = builder.get_minimal_bundle(
            agent_type="test",
            phase=Phase.RECON,
        )

        assert bundle.agent_type == "test"
        assert bundle.scope is not None


class TestContextBuilderIntegration:
    """Integration tests for context builder."""

    @pytest.fixture
    def full_state_store(self):
        """Create state store with full data."""
        store = MagicMock()
        store.get_version.return_value = 1

        def read_json_side_effect(path):
            if "scope" in path:
                return {"targets": [{"value": "10.0.0.1", "type": "ip"}]}
            elif "target_profile" in path:
                return {"ip": "10.0.0.1", "services": []}
            elif "execution_plans" in path:
                return {"plans": [{"action": "exploit"}]}
            return {}

        def read_jsonl_side_effect(path):
            if "observations" in path:
                return [{"type": "service", "port": 22}]
            elif "vuln_candidates" in path:
                return [{"cve": "CVE-2024-0001"}]
            elif "exploit_candidates" in path:
                return [{"name": "ssh_exploit"}]
            elif "execution_results" in path:
                return [{"step": 1, "success": True}]
            return []

        store.read_json.side_effect = read_json_side_effect
        store.read_jsonl.side_effect = read_jsonl_side_effect
        store.exists.return_value = True

        return store

    def test_full_context_for_exploitation_agent(self, full_state_store):
        """Test building full context for exploitation agent."""
        ledger = MagicMock()
        ledger.query.return_value = []

        builder = ContextBuilder(
            full_state_store,
            ledger,
            session_id="test",
            scope_tag="test",
        )

        bundle = builder.build(
            agent_type="exploitation_agent",
            phase=Phase.EXPLOITATION,
        )

        assert bundle.scope is not None
        assert bundle.execution_plans == [{"action": "exploit"}]
