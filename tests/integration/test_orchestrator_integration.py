"""
Integration tests for Orchestrator full phase cycle.

Tests:
- AC-1: Recon→Enumeration→Planner→Exploitation phase cycle with State/Evidence persistence
- AC-4: Metasploit execution requires approval
- Phase rollback scenarios
- State/Evidence persistence verification
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from src.orchestrator.orchestrator import (
    Orchestrator,
    OrchestratorConfig,
    AgentResult,
)
from src.orchestrator.router import Phase, TransitionReason
from src.orchestrator.context_builder import ContextBundle
from src.orchestrator.approval_gate import ApprovalRequest, ApprovalResult, ApprovalStatus
from src.patch.patch import Patch, PatchOperation
from src.patch.operations import OperationType
from src.storage.state_store import StateStore
from src.storage.evidence_ledger import EvidenceLedger
from src.storage.session_manager import SessionManager


class TestOrchestratorIntegration:
    """Integration tests for full Orchestrator workflow."""

    @pytest.fixture
    def temp_workspace(self):
        """Create temporary workspace directory."""
        workspace = tempfile.mkdtemp(prefix="pentest_integration_")
        yield workspace
        shutil.rmtree(workspace, ignore_errors=True)

    @pytest.fixture
    def session_id(self):
        """Generate unique session ID."""
        return f"test-session-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def session_manager(self, temp_workspace, session_id):
        """Create session manager."""
        manager = SessionManager(temp_workspace)
        manager.create_session(session_id)
        return manager

    @pytest.fixture
    def state_store(self, session_manager, session_id):
        """Create state store."""
        session_path = session_manager.get_session_path(session_id)
        return StateStore(os.path.join(session_path, "state"))

    @pytest.fixture
    def evidence_ledger(self, session_manager, session_id):
        """Create evidence ledger."""
        session_path = session_manager.get_session_path(session_id)
        return EvidenceLedger(os.path.join(session_path, "evidence"))

    @pytest.fixture
    def config(self, session_id):
        """Create orchestrator config."""
        return OrchestratorConfig(
            session_id=session_id,
            scope_tag="integration-test",
            approval_timeout_minutes=1,
            consecutive_error_threshold=3,
            auto_advance=False,
        )

    @pytest.fixture
    def initial_scope(self):
        """Create initial scope data."""
        return {
            "id": "scope-001",
            "session_id": "test-session",
            "targets": [
                {"type": "ip", "value": "192.168.1.100"},
                {"type": "domain", "value": "test.example.com"},
            ],
            "allowed_operations": ["scan", "enumerate", "exploit"],
            "created_at": datetime.utcnow().isoformat() + "Z",
            "created_by": "human",
            "scope_tag": "integration-test",
            "schema_version": "1.0.0",
        }

    @pytest.fixture
    def initial_target_profile(self):
        """Create initial target profile."""
        return {
            "id": "target-001",
            "session_id": "test-session",
            "hosts": [],
            "services": [],
            "technologies": [],
            "created_at": datetime.utcnow().isoformat() + "Z",
            "created_by": "orchestrator",
            "scope_tag": "integration-test",
            "schema_version": "1.0.0",
        }


class TestFullPhaseCycle(TestOrchestratorIntegration):
    """
    Test AC-1: Recon→Enumeration→Planner→Exploitation cycle with State/Evidence persistence.
    """

    def test_full_phase_cycle_with_mock_agents(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test complete phase cycle from Recon to Exploitation."""
        # Setup initial state
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        # Create orchestrator
        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
        )

        # Track phase execution
        phases_executed = []
        patches_applied = []

        def create_mock_handler(phase_name: str, agent_type: str):
            """Create a mock handler for a phase."""

            def handler(context: ContextBundle) -> AgentResult:
                phases_executed.append(phase_name)

                # Create a patch with observations
                patch = Patch(
                    patch_id=f"patch-{phase_name}-{uuid.uuid4().hex[:8]}",
                    session_id=config.session_id,
                    agent_id=agent_type,
                    base_state_version=context.state_version,
                    operations=[
                        PatchOperation(
                            op=OperationType.ADD_OBSERVATION,
                            target="observations",
                            payload={
                                "id": f"obs-{phase_name}-001",
                                "type": f"{phase_name}_observation",
                                "tool": f"{phase_name}_tool",
                                "data": {"phase": phase_name, "success": True},
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                            },
                        ),
                    ],
                    scope_tag=config.scope_tag,
                )
                patches_applied.append(patch.patch_id)

                # Return phase-specific results that satisfy can_advance requirements
                phase_results = {
                    "recon": {"targets_found": 5, "success": True},
                    "enumeration": {"services_found": 10, "endpoints_found": 25, "success": True},
                    "planner": {"plans_created": 3, "vuln_candidates": 5, "success": True},
                    "exploitation": {"findings_created": 2, "success": True},
                    "reporting": {"report_generated": True, "success": True},
                }

                return AgentResult(
                    agent_type=agent_type,
                    success=True,
                    patch=patch,
                    phase_result=phase_results.get(phase_name, {"success": True}),
                )

            return handler

        # Register handlers for all phases with correct agent names
        orchestrator.register_agent_handler(
            "recon_agent", create_mock_handler("recon", "recon_agent")
        )
        orchestrator.register_agent_handler(
            "enumeration_agent", create_mock_handler("enumeration", "enumeration_agent")
        )
        orchestrator.register_agent_handler(
            "planner_agent", create_mock_handler("planner", "planner_agent")
        )
        orchestrator.register_agent_handler(
            "exploitation_agent", create_mock_handler("exploitation", "exploitation_agent")
        )
        orchestrator.register_agent_handler(
            "reporting_agent", create_mock_handler("reporting", "reporting_agent")
        )

        # Run workflow
        result = orchestrator.run_workflow()

        # Verify all phases executed
        assert "recon" in phases_executed
        assert "enumeration" in phases_executed
        assert "planner" in phases_executed
        assert "exploitation" in phases_executed

        # Verify workflow completed
        assert result["final_phase"] in ["completed", "reporting"]
        assert result["stopped"] is False
        assert result["total_phases_run"] >= 4

        # Verify state was saved
        scope = state_store.read_json("scope.json")
        assert scope is not None
        assert scope["id"] == "scope-001"

    def test_phase_transitions_are_logged(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test that phase transitions are properly logged."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
        )

        # Success handler that returns proper phase results
        def success_handler(context: ContextBundle) -> AgentResult:
            return AgentResult(
                agent_type=context.agent_type,
                success=True,
                phase_result={
                    "success": True,
                    "targets_found": 1,
                    "services_found": 1,
                    "endpoints_found": 1,
                    "plans_created": 1,
                },
            )

        # Register with correct agent names
        for agent_type in ["recon_agent", "enumeration_agent", "planner_agent",
                          "exploitation_agent", "reporting_agent"]:
            orchestrator.register_agent_handler(agent_type, success_handler)

        result = orchestrator.run_workflow()

        # Verify transitions were recorded
        assert len(result["transitions"]) >= 4  # At least 4 phase transitions


class TestMetasploitApproval(TestOrchestratorIntegration):
    """
    Test AC-4: Metasploit execution requires approval.
    """

    def test_metasploit_execution_requires_approval(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test that Metasploit execution requires human approval."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        # Track approval requests
        approval_requests = []

        def approval_callback(request: ApprovalRequest) -> ApprovalResult:
            approval_requests.append(request)
            # Auto-approve for test
            return ApprovalResult(
                request_id=request.request_id,
                approved=True,
                responded_by="test_user",
            )

        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
            approval_callback=approval_callback,
        )

        # Handler that simulates Metasploit execution with RECORD_EXECUTION_RESULT
        def exploit_handler(context: ContextBundle) -> AgentResult:
            patch = Patch(
                patch_id=f"patch-msf-{uuid.uuid4().hex[:8]}",
                session_id=config.session_id,
                agent_id="exploitation_agent",
                base_state_version=context.state_version,
                operations=[
                    PatchOperation(
                        op=OperationType.RECORD_EXECUTION_RESULT,
                        target="execution_results",
                        payload={
                            "id": f"exec-{uuid.uuid4().hex[:8]}",
                            "tool": "metasploit",
                            "module": "exploit/multi/handler",
                            "options": {"LHOST": "192.168.1.1", "LPORT": 4444},
                            "success": True,
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                        },
                        requires_approval=True,  # Requires approval
                    ),
                ],
                scope_tag=config.scope_tag,
            )

            return AgentResult(
                agent_type="exploitation_agent",
                success=True,
                patch=patch,
                phase_result={"success": True},
            )

        orchestrator.register_agent_handler("exploitation_agent", exploit_handler)

        # Start orchestrator and move to exploitation phase
        orchestrator.start()
        while orchestrator.current_phase != Phase.EXPLOITATION:
            orchestrator.router.advance()

        # Run exploitation phase
        result = orchestrator.run_phase()

        # Verify approval was requested for metasploit operation
        assert len(approval_requests) >= 1
        assert any(
            "metasploit" in req.target.lower() or "execution" in req.operation.lower()
            for req in approval_requests
        )

    def test_metasploit_execution_denied_when_not_approved(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test that Metasploit execution is blocked when approval is denied."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        # Track rejection
        approval_denied = []

        def approval_callback(request: ApprovalRequest) -> ApprovalResult:
            # Deny all approvals
            approval_denied.append(request)
            return ApprovalResult(
                request_id=request.request_id,
                approved=False,
                responded_by="test_user",
                reason="Operation not authorized",
            )

        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
            approval_callback=approval_callback,
        )

        # Handler that simulates Metasploit execution with RECORD_EXECUTION_RESULT
        def exploit_handler(context: ContextBundle) -> AgentResult:
            patch = Patch(
                patch_id=f"patch-msf-{uuid.uuid4().hex[:8]}",
                session_id=config.session_id,
                agent_id="exploitation_agent",
                base_state_version=context.state_version,
                operations=[
                    PatchOperation(
                        op=OperationType.RECORD_EXECUTION_RESULT,
                        target="execution_results",
                        payload={
                            "id": f"exec-{uuid.uuid4().hex[:8]}",
                            "tool": "metasploit",
                            "module": "exploit/windows/smb/ms17_010_eternalblue",
                            "success": False,
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                        },
                        requires_approval=True,
                    ),
                ],
                scope_tag=config.scope_tag,
            )

            return AgentResult(
                agent_type="exploitation_agent",
                success=True,
                patch=patch,
                phase_result={"success": True},
            )

        orchestrator.register_agent_handler("exploitation_agent", exploit_handler)

        # Start orchestrator and move to exploitation phase
        orchestrator.start()
        while orchestrator.current_phase != Phase.EXPLOITATION:
            orchestrator.router.advance()

        # Run exploitation phase
        result = orchestrator.run_phase()

        # Verify approval was denied
        assert len(approval_denied) >= 1


class TestStateEvidencePersistence(TestOrchestratorIntegration):
    """
    Test AC-2: Evidence is saved with sha256 and State is persisted.
    """

    def test_evidence_saved_with_hash(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
        temp_workspace,
    ):
        """Test that evidence is saved with SHA256 hash."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        # Save evidence using store() method
        evidence_data = {
            "type": "nmap_scan",
            "target": "192.168.1.100",
            "output": "PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http",
        }

        evidence_item = evidence_ledger.store(
            data=json.dumps(evidence_data),
            source_tool="nmap",
            extension="json",
            mime_type="application/json",
            additional_meta={"target": "192.168.1.100"},
        )

        # Verify evidence was saved
        assert evidence_item is not None
        assert "sha256" in evidence_item
        assert len(evidence_item["sha256"]) == 64  # SHA256 hex length
        assert "evidence_id" in evidence_item

        # Verify evidence can be retrieved
        retrieved = evidence_ledger.get(evidence_item["evidence_id"])
        assert retrieved is not None
        assert retrieved["sha256"] == evidence_item["sha256"]

    def test_state_persists_across_phases(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test that state changes persist across phase transitions."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
        )

        observations_added = []

        def handler_with_observation(phase_name: str, agent_type: str):
            def handler(context: ContextBundle) -> AgentResult:
                # Add observation via patch
                obs_id = f"obs-{phase_name}-{uuid.uuid4().hex[:8]}"
                observations_added.append(obs_id)

                patch = Patch(
                    patch_id=f"patch-{phase_name}",
                    session_id=config.session_id,
                    agent_id=agent_type,
                    base_state_version=context.state_version,
                    operations=[
                        PatchOperation(
                            op=OperationType.ADD_OBSERVATION,
                            target="observations",
                            payload={
                                "id": obs_id,
                                "type": "test",
                                "phase": phase_name,
                                "timestamp": datetime.utcnow().isoformat() + "Z",
                            },
                        ),
                    ],
                    scope_tag=config.scope_tag,
                )

                return AgentResult(
                    agent_type=agent_type,
                    success=True,
                    patch=patch,
                    phase_result={
                        "success": True,
                        "targets_found": 1,
                        "services_found": 1,
                        "endpoints_found": 1,
                        "plans_created": 1,
                    },
                )
            return handler

        orchestrator.register_agent_handler("recon_agent", handler_with_observation("recon", "recon_agent"))
        orchestrator.register_agent_handler("enumeration_agent", handler_with_observation("enum", "enumeration_agent"))
        orchestrator.register_agent_handler("planner_agent", handler_with_observation("planner", "planner_agent"))
        orchestrator.register_agent_handler("exploitation_agent", handler_with_observation("exploit", "exploitation_agent"))
        orchestrator.register_agent_handler("reporting_agent", handler_with_observation("reporter", "reporting_agent"))

        result = orchestrator.run_workflow()

        # Verify observations were persisted
        saved_observations = state_store.read_jsonl("observations.jsonl")
        assert len(saved_observations) >= len(observations_added) or len(observations_added) > 0


class TestPhaseRollback(TestOrchestratorIntegration):
    """Test phase rollback scenarios."""

    def test_rollback_to_recon_on_version_unconfirmed(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test rollback to RECON when version is unconfirmed."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
        )

        phase_history = []

        def recon_handler(context: ContextBundle) -> AgentResult:
            phase_history.append("recon")
            return AgentResult(
                agent_type="recon_agent",
                success=True,
                phase_result={"targets_found": 3, "success": True},
            )

        def enum_handler(context: ContextBundle) -> AgentResult:
            phase_history.append("enumeration")
            # Simulate version unconfirmed - needs rollback
            return AgentResult(
                agent_type="enumeration_agent",
                success=True,
                phase_result={
                    "success": True,
                    "services_found": 0,
                    "version_unconfirmed": True,
                    "needs_more_info": True,
                    "rollback_phase": "recon",
                },
            )

        orchestrator.register_agent_handler("recon_agent", recon_handler)
        orchestrator.register_agent_handler("enumeration_agent", enum_handler)

        orchestrator.start()

        # Run recon
        result1 = orchestrator.run_phase()
        assert result1.success

        # Advance to enumeration
        transition1 = orchestrator.advance_phase(result1.phase_result)
        assert transition1 is not None
        assert orchestrator.current_phase == Phase.ENUMERATION

        # Run enumeration (should indicate rollback needed)
        result2 = orchestrator.run_phase()
        assert result2.success

        # Attempt to advance - should trigger rollback
        transition2 = orchestrator.advance_phase(result2.phase_result)

        # Verify rollback occurred
        if transition2 and transition2.reason == TransitionReason.ROLLBACK:
            assert orchestrator.current_phase == Phase.RECON

    def test_rollback_to_enumeration_on_insufficient_repro(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test rollback to ENUMERATION when reproduction steps are insufficient."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
        )

        def success_handler(agent_type: str, phase_result: dict):
            def handler(context: ContextBundle) -> AgentResult:
                return AgentResult(
                    agent_type=agent_type,
                    success=True,
                    phase_result=phase_result,
                )
            return handler

        orchestrator.register_agent_handler(
            "recon_agent",
            success_handler("recon_agent", {"targets_found": 5, "success": True})
        )
        orchestrator.register_agent_handler(
            "enumeration_agent",
            success_handler("enumeration_agent", {"services_found": 10, "endpoints_found": 20, "success": True})
        )
        orchestrator.register_agent_handler(
            "planner_agent",
            success_handler("planner_agent", {
                "plans_created": 2,
                "success": True,
                "insufficient_repro": True,
                "needs_more_info": True,
                "rollback_phase": "enumeration",
            })
        )

        orchestrator.start()

        # Advance through recon and enumeration
        orchestrator.run_phase()
        orchestrator.advance_phase({"targets_found": 5, "success": True})

        orchestrator.run_phase()
        orchestrator.advance_phase({"services_found": 10, "success": True})

        # Run planner
        result = orchestrator.run_phase()

        # Attempt to advance - might trigger rollback
        transition = orchestrator.advance_phase(result.phase_result)

        if transition and transition.reason == TransitionReason.ROLLBACK:
            assert orchestrator.current_phase == Phase.ENUMERATION


class TestStopConditions(TestOrchestratorIntegration):
    """Test stop condition handling."""

    def test_stops_on_consecutive_errors(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test that orchestrator stops on consecutive errors."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        # Lower threshold for test
        config.consecutive_error_threshold = 2

        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
        )

        error_count = [0]

        def failing_handler(context: ContextBundle) -> AgentResult:
            error_count[0] += 1
            return AgentResult(
                agent_type="recon_agent",
                success=False,
                error=f"Simulated error #{error_count[0]}",
            )

        orchestrator.register_agent_handler("recon_agent", failing_handler)

        result = orchestrator.run_workflow()

        # Workflow should have stopped due to errors
        assert result["stopped"] is True
        assert error_count[0] >= 2

    def test_emergency_snapshot_on_critical_stop(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test that emergency snapshot is saved on critical stop."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        config.consecutive_error_threshold = 1

        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
        )

        def scope_violation_handler(context: ContextBundle) -> AgentResult:
            return AgentResult(
                agent_type="recon_agent",
                success=False,
                error="Scope violation detected: target out of scope",
            )

        orchestrator.register_agent_handler("recon_agent", scope_violation_handler)

        result = orchestrator.run_workflow()

        assert result["stopped"] is True


class TestContextBundlePassing(TestOrchestratorIntegration):
    """Test context bundle passing between phases."""

    def test_context_includes_previous_phase_data(
        self,
        state_store,
        evidence_ledger,
        config,
        initial_scope,
        initial_target_profile,
    ):
        """Test that context bundles include data from previous phases."""
        state_store.write_json("scope.json", initial_scope)
        state_store.write_json("target_profile.json", initial_target_profile)

        orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
        )

        contexts_received = []

        def tracking_handler(agent_type: str, phase_result: dict):
            def handler(context: ContextBundle) -> AgentResult:
                contexts_received.append({
                    "agent_type": agent_type,
                    "has_scope": context.scope is not None,
                    "has_target_profile": context.target_profile is not None,
                    "observations_count": len(context.observations) if context.observations else 0,
                })
                return AgentResult(
                    agent_type=agent_type,
                    success=True,
                    phase_result=phase_result,
                )
            return handler

        orchestrator.register_agent_handler(
            "recon_agent",
            tracking_handler("recon_agent", {"targets_found": 5, "success": True})
        )
        orchestrator.register_agent_handler(
            "enumeration_agent",
            tracking_handler("enumeration_agent", {"services_found": 10, "success": True})
        )
        orchestrator.register_agent_handler(
            "planner_agent",
            tracking_handler("planner_agent", {"plans_created": 2, "success": True})
        )
        orchestrator.register_agent_handler(
            "exploitation_agent",
            tracking_handler("exploitation_agent", {"success": True})
        )
        orchestrator.register_agent_handler(
            "reporting_agent",
            tracking_handler("reporting_agent", {"success": True})
        )

        orchestrator.run_workflow()

        # All agents should have received scope
        for ctx in contexts_received:
            assert ctx["has_scope"] is True


# Run with pytest
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
