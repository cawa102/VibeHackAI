"""Tests for orchestrator router."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock
from datetime import datetime

from src.orchestrator.router import (
    Router,
    Phase,
    PhaseTransition,
    TransitionReason,
    PHASE_ORDER,
    PHASE_AGENTS,
)


class TestPhase:
    """Tests for Phase enum."""

    def test_all_phases_defined(self):
        """Test all expected phases are defined."""
        expected = [
            "init", "recon", "enumeration", "planner",
            "exploitation", "reporting", "completed", "stopped"
        ]
        for phase_name in expected:
            assert hasattr(Phase, phase_name.upper())

    def test_phase_values(self):
        """Test phase values are correct."""
        assert Phase.INIT.value == "init"
        assert Phase.RECON.value == "recon"
        assert Phase.COMPLETED.value == "completed"


class TestPhaseTransition:
    """Tests for PhaseTransition dataclass."""

    def test_create_transition(self):
        """Test creating a phase transition."""
        transition = PhaseTransition(
            from_phase=Phase.RECON,
            to_phase=Phase.ENUMERATION,
            reason=TransitionReason.NORMAL,
            timestamp=datetime.utcnow(),
        )

        assert transition.from_phase == Phase.RECON
        assert transition.to_phase == Phase.ENUMERATION
        assert transition.reason == TransitionReason.NORMAL

    def test_transition_to_dict(self):
        """Test converting transition to dict."""
        transition = PhaseTransition(
            from_phase=Phase.RECON,
            to_phase=Phase.ENUMERATION,
            reason=TransitionReason.NORMAL,
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            details="Test transition",
        )

        result = transition.to_dict()

        assert result["from_phase"] == "recon"
        assert result["to_phase"] == "enumeration"
        assert result["reason"] == "normal"
        assert result["details"] == "Test transition"


class TestRouter:
    """Tests for Router class."""

    @pytest.fixture
    def mock_state_store(self):
        """Create mock state store."""
        store = MagicMock()
        store.read_json.return_value = {}
        return store

    @pytest.fixture
    def router(self, mock_state_store):
        """Create router instance."""
        return Router(mock_state_store)

    def test_initial_phase(self, router):
        """Test router starts at INIT phase."""
        assert router.current_phase == Phase.INIT

    def test_advance_from_init(self, router):
        """Test advancing from INIT to RECON."""
        transition = router.advance()

        assert transition.from_phase == Phase.INIT
        assert transition.to_phase == Phase.RECON
        assert router.current_phase == Phase.RECON

    def test_advance_through_phases(self, router):
        """Test advancing through all phases."""
        phases = [Phase.INIT, Phase.RECON, Phase.ENUMERATION,
                  Phase.PLANNER, Phase.EXPLOITATION, Phase.REPORTING]

        for i, expected_phase in enumerate(phases[:-1]):
            assert router.current_phase == expected_phase
            transition = router.advance()
            assert transition.from_phase == expected_phase
            assert transition.to_phase == phases[i + 1]

    def test_advance_to_completed(self, router):
        """Test advancing to COMPLETED phase."""
        # Advance to REPORTING
        for _ in range(5):
            router.advance()

        assert router.current_phase == Phase.REPORTING

        # Advance to COMPLETED
        transition = router.advance()
        assert transition.to_phase == Phase.COMPLETED
        assert router.current_phase == Phase.COMPLETED

    def test_cannot_advance_from_completed(self, router):
        """Test cannot advance from COMPLETED."""
        # Advance to COMPLETED
        for _ in range(6):
            router.advance()

        assert router.current_phase == Phase.COMPLETED

        # Try to advance - should raise ValueError
        with pytest.raises(ValueError, match="Cannot advance"):
            router.advance()

    def test_stop(self, router):
        """Test stopping the router."""
        router.advance()  # Move to RECON
        router.stop("Test stop", "user")

        assert router.current_phase == Phase.STOPPED

    def test_rollback(self, router):
        """Test rolling back to a previous phase."""
        router.advance()  # INIT -> RECON
        router.advance()  # RECON -> ENUMERATION

        transition = router.rollback_to(Phase.RECON, details="Need more info")

        assert transition.from_phase == Phase.ENUMERATION
        assert transition.to_phase == Phase.RECON
        assert transition.reason == TransitionReason.ROLLBACK

    def test_skip_to(self, router):
        """Test skipping to a later phase."""
        router.advance()  # INIT -> RECON

        transition = router.skip_to(Phase.PLANNER, details="Skip enum")

        assert transition.from_phase == Phase.RECON
        assert transition.to_phase == Phase.PLANNER
        assert transition.reason == TransitionReason.SKIP

    def test_get_current_agent(self, router):
        """Test getting agent for current phase."""
        router.advance()  # Move to RECON
        agent = router.get_current_agent()

        assert agent == PHASE_AGENTS.get(Phase.RECON)

    def test_get_next_phase(self, router):
        """Test getting next phase."""
        next_phase = router.get_next_phase()
        assert next_phase == Phase.RECON

        router.advance()
        next_phase = router.get_next_phase()
        assert next_phase == Phase.ENUMERATION

    def test_can_advance_simple(self, router):
        """Test can_advance from INIT (no phase result needed)."""
        # From INIT, can advance without phase result
        assert router.can_advance() is True
        assert router.can_advance({}) is True

        router.advance()  # INIT -> RECON
        # From RECON, need phase result with targets_found
        assert router.can_advance({}) is False
        assert router.can_advance({"targets_found": 1}) is True

    def test_can_advance_with_blocking_error(self, router):
        """Test can_advance with blocking error."""
        router.advance()  # Move to RECON

        result = {"has_blocking_error": True}
        assert router.can_advance(result) is False

    def test_should_rollback(self, router):
        """Test should_rollback detection."""
        router.advance()  # INIT -> RECON
        router.advance({"targets_found": 1})  # RECON -> ENUMERATION

        # Version not confirmed should trigger rollback to RECON
        result = {"rollback_reason": "version_unconfirmed"}
        rollback_phase = router.should_rollback(result)
        assert rollback_phase == Phase.RECON

        # Insufficient repro should trigger rollback to ENUMERATION
        result = {"rollback_reason": "insufficient_repro"}
        rollback_phase = router.should_rollback(result)
        assert rollback_phase == Phase.ENUMERATION

        # No rollback reason should return None
        result = {"some_other_key": True}
        rollback_phase = router.should_rollback(result)
        assert rollback_phase is None

    def test_should_skip(self, router):
        """Test should_skip detection."""
        # General sufficient_info flag
        result = {"sufficient_info": True}
        assert router.should_skip(result) is True

        # No skip flags
        result = {"some_other_key": True}
        assert router.should_skip(result) is False

        # Phase-specific skip (from RECON)
        router.advance()  # INIT -> RECON
        result = {"external_intel_sufficient": True}
        assert router.should_skip(result) is True

    def test_get_state(self, router):
        """Test getting router state."""
        state = router.get_state()

        assert "current_phase" in state
        assert "transitions_count" in state
        assert "phase_results" in state
        assert state["current_phase"] == "init"
        assert state["transitions_count"] == 0

    def test_phase_result_stored(self, router):
        """Test phase result is stored."""
        router.advance()  # INIT -> RECON

        phase_result = {"findings": ["test"]}
        router.advance(phase_result)

        stored_result = router.get_phase_result(Phase.RECON)
        assert stored_result == phase_result


class TestPhaseOrder:
    """Tests for phase ordering."""

    def test_phase_order_complete(self):
        """Test PHASE_ORDER contains all workflow phases."""
        expected = [
            Phase.INIT, Phase.RECON, Phase.ENUMERATION,
            Phase.PLANNER, Phase.EXPLOITATION, Phase.REPORTING,
            Phase.COMPLETED
        ]
        assert PHASE_ORDER == expected

    def test_phase_agents_defined(self):
        """Test agents are defined for relevant phases."""
        assert Phase.RECON in PHASE_AGENTS
        assert Phase.ENUMERATION in PHASE_AGENTS
        assert Phase.PLANNER in PHASE_AGENTS
        assert Phase.EXPLOITATION in PHASE_AGENTS
        assert Phase.REPORTING in PHASE_AGENTS
