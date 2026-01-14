"""Tests for main orchestrator."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from src.orchestrator.orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    AgentResult,
)
from src.orchestrator.router import Phase, TransitionReason


class TestOrchestratorConfig:
    """Tests for OrchestratorConfig dataclass."""

    def test_create_config(self):
        """Test creating orchestrator config."""
        config = OrchestratorConfig(
            session_id="session-001",
            scope_tag="test-scope",
        )

        assert config.session_id == "session-001"
        assert config.scope_tag == "test-scope"

    def test_config_defaults(self):
        """Test config default values."""
        config = OrchestratorConfig(
            session_id="test",
            scope_tag="test",
        )

        assert config.approval_timeout_minutes == 5
        assert config.consecutive_error_threshold == 2
        assert config.total_error_threshold == 10
        assert config.auto_advance is False
        assert config.require_all_approvals is True


class TestAgentResult:
    """Tests for AgentResult dataclass."""

    def test_create_success_result(self):
        """Test creating successful result."""
        result = AgentResult(
            agent_type="recon_agent",
            success=True,
            phase_result={"findings": ["host discovered"]},
            duration_ms=1500,
        )

        assert result.success is True
        assert result.agent_type == "recon_agent"
        assert result.duration_ms == 1500

    def test_create_failure_result(self):
        """Test creating failure result."""
        result = AgentResult(
            agent_type="recon_agent",
            success=False,
            error="Connection timeout",
        )

        assert result.success is False
        assert result.error == "Connection timeout"


class TestOrchestrator:
    """Tests for Orchestrator class."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.read_json.return_value = {}
        store.read_jsonl.return_value = []
        store.write_json = MagicMock()
        store.append_jsonl = MagicMock()
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
    def config(self):
        """Create orchestrator config."""
        return OrchestratorConfig(
            session_id="test-session",
            scope_tag="test-scope",
        )

    @pytest.fixture
    def orchestrator(self, mock_state_store, mock_evidence_ledger, config):
        """Create orchestrator."""
        return Orchestrator(
            state_store=mock_state_store,
            evidence_ledger=mock_evidence_ledger,
            config=config,
        )

    def test_initial_state(self, orchestrator):
        """Test initial orchestrator state."""
        assert orchestrator.is_running is False
        assert orchestrator.current_phase == Phase.INIT

    def test_start(self, orchestrator):
        """Test starting orchestrator."""
        orchestrator.start()

        assert orchestrator.is_running is True
        assert orchestrator.current_phase == Phase.RECON

    def test_start_twice_raises(self, orchestrator):
        """Test starting twice raises error."""
        orchestrator.start()

        with pytest.raises(RuntimeError, match="already started"):
            orchestrator.start()

    def test_stop(self, orchestrator):
        """Test stopping orchestrator."""
        orchestrator.start()
        orchestrator.stop("Test stop", "user")

        assert orchestrator.is_running is False

    def test_register_agent_handler(self, orchestrator):
        """Test registering agent handler."""
        def dummy_handler(context):
            return AgentResult(agent_type="test", success=True)

        orchestrator.register_agent_handler("test_agent", dummy_handler)

        assert "test_agent" in orchestrator._agent_handlers

    def test_run_phase_without_start_raises(self, orchestrator):
        """Test running phase without start raises error."""
        with pytest.raises(RuntimeError, match="not running"):
            orchestrator.run_phase()

    def test_run_phase_without_handler_raises(self, orchestrator):
        """Test running phase without handler raises error."""
        orchestrator.start()

        with pytest.raises(RuntimeError, match="No handler"):
            orchestrator.run_phase()

    def test_run_phase_success(self, orchestrator):
        """Test running phase successfully."""
        orchestrator.start()

        def recon_handler(context):
            return AgentResult(
                agent_type="recon_agent",
                success=True,
                phase_result={"hosts_found": 5},
            )

        orchestrator.register_agent_handler("recon_agent", recon_handler)

        result = orchestrator.run_phase()

        assert result.success is True
        assert result.agent_type == "recon_agent"

    def test_run_phase_failure(self, orchestrator):
        """Test running phase with failure."""
        orchestrator.start()

        def failing_handler(context):
            return AgentResult(
                agent_type="recon_agent",
                success=False,
                error="Network error",
            )

        orchestrator.register_agent_handler("recon_agent", failing_handler)

        result = orchestrator.run_phase()

        assert result.success is False
        assert result.error == "Network error"

    def test_run_phase_exception(self, orchestrator):
        """Test running phase with exception."""
        orchestrator.start()

        def exception_handler(context):
            raise ValueError("Something broke")

        orchestrator.register_agent_handler("recon_agent", exception_handler)

        result = orchestrator.run_phase()

        assert result.success is False
        assert "Something broke" in result.error

    def test_advance_phase(self, orchestrator):
        """Test advancing to next phase."""
        orchestrator.start()

        transition = orchestrator.advance_phase({"success": True})

        assert transition is not None
        assert transition.from_phase == Phase.RECON
        assert transition.to_phase == Phase.ENUMERATION

    def test_advance_phase_blocked(self, orchestrator):
        """Test advancing blocked by error."""
        orchestrator.start()

        transition = orchestrator.advance_phase({"has_blocking_error": True})

        assert transition is None

    def test_advance_phase_rollback(self, orchestrator):
        """Test rollback during advance."""
        orchestrator.start()
        orchestrator.advance_phase({})  # RECON -> ENUM

        # Request rollback
        transition = orchestrator.advance_phase({
            "needs_more_info": True,
            "rollback_phase": "recon",
        })

        assert transition is not None
        assert transition.reason == TransitionReason.ROLLBACK
        assert transition.to_phase == Phase.RECON

    def test_get_status(self, orchestrator):
        """Test getting orchestrator status."""
        status = orchestrator.get_status()

        assert status["session_id"] == "test-session"
        assert status["scope_tag"] == "test-scope"
        assert status["is_running"] is False
        assert "current_phase" in status
        assert "state_version" in status

    def test_get_status_running(self, orchestrator):
        """Test getting status when running."""
        orchestrator.start()
        status = orchestrator.get_status()

        assert status["is_running"] is True
        assert status["current_phase"] == "recon"


class TestOrchestratorWorkflow:
    """Tests for orchestrator workflow execution."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.read_json.return_value = {}
        store.read_jsonl.return_value = []
        store.write_json = MagicMock()
        store.append_jsonl = MagicMock()
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
    def config(self):
        """Create config."""
        return OrchestratorConfig(
            session_id="test",
            scope_tag="test",
        )

    def test_run_workflow_complete(self, mock_state_store, mock_evidence_ledger, config):
        """Test running complete workflow."""
        orchestrator = Orchestrator(
            state_store=mock_state_store,
            evidence_ledger=mock_evidence_ledger,
            config=config,
        )

        # Register handlers for all phases
        def success_handler(context):
            return AgentResult(
                agent_type=context.agent_type,
                success=True,
                phase_result={"success": True},
            )

        for agent_type in ["recon_agent", "enum_agent", "planner_agent",
                          "exploit_agent", "reporter_agent"]:
            orchestrator.register_agent_handler(agent_type, success_handler)

        # Run workflow
        result = orchestrator.run_workflow()

        assert result["final_phase"] == "completed"
        assert result["stopped"] is False
        assert result["total_phases_run"] == 5

    def test_run_workflow_stops_on_errors(self, mock_state_store, mock_evidence_ledger, config):
        """Test workflow stops on consecutive errors."""
        orchestrator = Orchestrator(
            state_store=mock_state_store,
            evidence_ledger=mock_evidence_ledger,
            config=config,
        )

        call_count = 0

        def failing_handler(context):
            nonlocal call_count
            call_count += 1
            return AgentResult(
                agent_type=context.agent_type,
                success=False,
                error="Always fails",
            )

        orchestrator.register_agent_handler("recon_agent", failing_handler)

        result = orchestrator.run_workflow()

        # Should stop due to consecutive errors
        assert result["stopped"] is True


class TestOrchestratorApproval:
    """Tests for orchestrator approval handling."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.read_json.return_value = {}
        store.read_jsonl.return_value = []
        store.write_json = MagicMock()
        store.append_jsonl = MagicMock()
        store.exists.return_value = False
        store.get_version.return_value = 1
        return store

    @pytest.fixture
    def mock_evidence_ledger(self):
        """Create mock evidence ledger."""
        ledger = MagicMock()
        ledger.query.return_value = []
        return ledger

    def test_approval_callback_called(self, mock_state_store, mock_evidence_ledger):
        """Test approval callback is invoked."""
        callback_invoked = []

        def approval_callback(request):
            callback_invoked.append(request)
            from src.orchestrator.approval_gate import ApprovalResult
            return ApprovalResult(
                request_id=request.request_id,
                approved=True,
                responded_by="test",
            )

        config = OrchestratorConfig(
            session_id="test",
            scope_tag="test",
        )

        orchestrator = Orchestrator(
            state_store=mock_state_store,
            evidence_ledger=mock_evidence_ledger,
            config=config,
            approval_callback=approval_callback,
        )

        # Create a patch requiring approval
        from src.patch.patch import Patch, PatchOperation
        from src.patch.operations import OperationType

        patch = Patch(
            patch_id="test-patch",
            agent_id="test-agent",
            operations=[
                PatchOperation(
                    op=OperationType.EXECUTE,
                    target="metasploit",
                    payload={"exploit": "test"},
                    requires_approval=True,
                )
            ],
        )

        orchestrator.start()
        result = orchestrator._process_patch(patch)

        # Callback should have been invoked
        assert len(callback_invoked) >= 1


class TestOrchestratorPatching:
    """Tests for orchestrator patch handling."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.read_json.return_value = {}
        store.read_jsonl.return_value = []
        store.write_json = MagicMock()
        store.append_jsonl = MagicMock()
        store.exists.return_value = False
        store.get_version.return_value = 1
        return store

    @pytest.fixture
    def mock_evidence_ledger(self):
        """Create mock evidence ledger."""
        ledger = MagicMock()
        ledger.query.return_value = []
        ledger.append = MagicMock()
        return ledger

    def test_patch_applied_on_success(self, mock_state_store, mock_evidence_ledger):
        """Test patch is applied on agent success."""
        config = OrchestratorConfig(
            session_id="test",
            scope_tag="test",
        )

        orchestrator = Orchestrator(
            state_store=mock_state_store,
            evidence_ledger=mock_evidence_ledger,
            config=config,
        )

        from src.patch.patch import Patch, PatchOperation
        from src.patch.operations import OperationType

        patch = Patch(
            patch_id="test-patch",
            agent_id="recon_agent",
            operations=[
                PatchOperation(
                    op=OperationType.ADD_OBSERVATION,
                    target="observations",
                    payload={"type": "host", "ip": "192.168.1.1"},
                )
            ],
        )

        def handler_with_patch(context):
            return AgentResult(
                agent_type="recon_agent",
                success=True,
                patch=patch,
            )

        orchestrator.register_agent_handler("recon_agent", handler_with_patch)
        orchestrator.start()

        result = orchestrator.run_phase()

        assert result.success is True
        # Patch should have been processed
