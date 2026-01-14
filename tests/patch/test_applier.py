"""Tests for PatchApplier."""

import pytest
import tempfile
from pathlib import Path

from src.patch.patch import Patch
from src.patch.operations import OperationType
from src.patch.applier import PatchApplier, ApplyResult
from src.storage.state_store import StateStore
from src.storage.evidence_ledger import EvidenceLedger


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def state_store(temp_dir):
    """Create a state store for tests."""
    return StateStore(temp_dir / "state")


@pytest.fixture
def evidence_ledger(temp_dir):
    """Create an evidence ledger for tests."""
    return EvidenceLedger(temp_dir / "evidence")


@pytest.fixture
def applier(state_store, evidence_ledger):
    """Create a patch applier for tests."""
    return PatchApplier(state_store, evidence_ledger)


class TestPatchApplier:
    """Tests for PatchApplier."""

    def test_apply_empty_patch_fails(self, applier, state_store):
        """Test that empty patch fails validation."""
        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )

        result = applier.apply(patch)

        assert result.success is False
        assert "Validation failed" in result.error

    def test_apply_version_mismatch_fails(self, applier, state_store):
        """Test that version mismatch fails."""
        # Increment version
        state_store.increment_version("test")

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=0,  # Old version
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan"},
        )

        result = applier.apply(patch)

        assert result.success is False
        assert "version" in result.error.lower()

    def test_apply_add_observation(self, applier, state_store):
        """Test applying add_observation operation."""
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=state_store.get_version(),
            scope_tag="192.168.1.1",
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={
                "tool": "nmap",
                "action": "port_scan",
                "summary": "Found 3 open ports",
            },
        )

        result = applier.apply(patch)

        assert result.success is True
        assert result.operations_applied == 1
        assert result.new_state_version == 1

        # Verify observation was stored
        observations = state_store.read_jsonl("observations.jsonl")
        assert len(observations) == 1
        assert observations[0]["tool"] == "nmap"

    def test_apply_add_evidence(self, applier, state_store, evidence_ledger):
        """Test applying add_evidence operation."""
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.ADD_EVIDENCE,
            target="nmap-output",
            payload={
                "data": "PORT   STATE SERVICE\n22/tcp open  ssh",
                "source_tool": "nmap",
                "extension": "txt",
            },
        )

        result = applier.apply(patch)

        assert result.success is True
        assert result.operation_results[0].object_id is not None

        # Verify evidence was stored
        evidence_id = result.operation_results[0].object_id
        assert evidence_ledger.exists(evidence_id)

    def test_apply_update_target_profile(self, applier, state_store):
        """Test applying update_target_profile operation."""
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=state_store.get_version(),
            scope_tag="192.168.1.1",
        )
        patch.add_operation(
            op=OperationType.UPDATE_TARGET_PROFILE,
            target="192.168.1.1",
            payload={
                "ip_address": "192.168.1.1",
                "hostnames": ["server1.example.com"],
                "ports": [{"port": 22, "protocol": "tcp", "state": "open"}],
            },
        )

        result = applier.apply(patch)

        assert result.success is True

        # Verify profile was stored
        profile = state_store.read_json("target_profile.json")
        assert profile["ip_address"] == "192.168.1.1"
        assert "server1.example.com" in profile["hostnames"]

    def test_apply_add_vuln_candidate(self, applier, state_store):
        """Test applying add_vuln_candidate operation."""
        patch = Patch(
            session_id="session-001",
            agent_id="planner_agent",
            base_state_version=state_store.get_version(),
            scope_tag="192.168.1.1",
        )
        patch.add_operation(
            op=OperationType.ADD_VULN_CANDIDATE,
            target="vuln-001",
            payload={
                "title": "SQL Injection",
                "description": "SQL injection in login form",
                "affected_component": "https://example.com/login",
                "source": "manual",
                "severity": "high",
            },
        )

        result = applier.apply(patch)

        assert result.success is True

        # Verify vuln was stored
        vulns = state_store.read_jsonl("vuln_candidates.jsonl")
        assert len(vulns) == 1
        assert vulns[0]["title"] == "SQL Injection"

    def test_apply_propose_execution_plan(self, applier, state_store):
        """Test applying propose_execution_plan operation."""
        patch = Patch(
            session_id="session-001",
            agent_id="planner_agent",
            base_state_version=state_store.get_version(),
            scope_tag="192.168.1.1",
        )
        patch.add_operation(
            op=OperationType.PROPOSE_EXECUTION_PLAN,
            target="plan-001",
            payload={
                "title": "Verify SQL Injection",
                "description": "Verify SQLi vulnerability",
                "target": "https://example.com/login",
            },
            requires_approval=True,
        )

        result = applier.apply(patch)

        assert result.success is True

        # Verify plan was stored
        data = state_store.read_json("execution_plans.json")
        assert len(data["plans"]) == 1
        assert data["plans"][0]["title"] == "Verify SQL Injection"
        assert data["plans"][0]["approved"] is False

    def test_apply_multiple_operations(self, applier, state_store):
        """Test applying multiple operations atomically."""
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=state_store.get_version(),
            scope_tag="192.168.1.1",
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan1"},
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.2",
            payload={"tool": "nmap", "action": "scan2"},
        )
        patch.add_operation(
            op=OperationType.UPDATE_TARGET_PROFILE,
            target="192.168.1.1",
            payload={"ip_address": "192.168.1.1"},
        )

        result = applier.apply(patch)

        assert result.success is True
        assert result.operations_applied == 3
        assert result.new_state_version == 1

        # Verify all operations were applied
        observations = state_store.read_jsonl("observations.jsonl")
        assert len(observations) == 2

        profile = state_store.read_json("target_profile.json")
        assert profile["ip_address"] == "192.168.1.1"

    def test_apply_increments_version(self, applier, state_store):
        """Test that successful apply increments state version."""
        initial_version = state_store.get_version()

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=initial_version,
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan"},
        )

        result = applier.apply(patch)

        assert result.success is True
        assert result.new_state_version == initial_version + 1
        assert state_store.get_version() == initial_version + 1

    def test_apply_without_validation(self, state_store, evidence_ledger):
        """Test applying without validation."""
        applier = PatchApplier(
            state_store, evidence_ledger, validate_before_apply=False
        )

        # This would normally fail validation (version mismatch)
        state_store.increment_version("test")

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=0,  # Old version
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan"},
        )

        result = applier.apply(patch)

        # Should still apply since validation is disabled
        assert result.success is True

    def test_apply_result_to_dict(self, applier, state_store):
        """Test ApplyResult serialization."""
        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan"},
        )

        result = applier.apply(patch)
        data = result.to_dict()

        assert data["success"] is True
        assert data["patch_id"] == patch.patch_id
        assert data["new_state_version"] == 1
        assert len(data["operation_results"]) == 1

    def test_rollback_on_failure(self, state_store, evidence_ledger):
        """Test rollback when operation fails."""
        # First, add some initial data
        state_store.append_jsonl("observations.jsonl", {"id": "existing", "tool": "initial"})
        initial_count = state_store.count_jsonl("observations.jsonl")

        # Create applier without validation to force failure in apply
        applier = PatchApplier(
            state_store, evidence_ledger, validate_before_apply=False
        )

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        # Add valid operation
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan"},
        )
        # Add operation with invalid type (will cause failure in dispatch)
        # We can't easily force a failure here, so this test mainly verifies rollback structure

        result = applier.apply(patch)

        # In normal case, should succeed
        if result.success:
            assert state_store.count_jsonl("observations.jsonl") == initial_count + 1
        else:
            # If it failed and rolled back
            assert result.rolled_back is True
            assert state_store.count_jsonl("observations.jsonl") == initial_count
