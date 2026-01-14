"""Tests for PatchAuditLog."""

import pytest
import tempfile
from datetime import datetime
from pathlib import Path

from src.patch.patch import Patch
from src.patch.operations import OperationType
from src.patch.applier import PatchApplier, ApplyResult
from src.patch.audit_log import PatchAuditLog, AuditAction, AuditEntry
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
def audit_log(state_store):
    """Create an audit log for tests."""
    return PatchAuditLog(state_store)


@pytest.fixture
def applier(state_store, evidence_ledger):
    """Create a patch applier for tests."""
    return PatchApplier(state_store, evidence_ledger)


class TestPatchAuditLog:
    """Tests for PatchAuditLog."""

    def test_record_successful_apply(self, audit_log, applier, state_store):
        """Test recording successful patch application."""
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan"},
        )

        result = applier.apply(patch)
        entry = audit_log.record(patch, result)

        assert entry.action == AuditAction.APPLIED
        assert entry.success is True
        assert entry.patch_id == patch.patch_id
        assert entry.agent_id == "recon_agent"
        assert entry.new_version == 1

    def test_record_failed_validation(self, audit_log, state_store):
        """Test recording validation rejection."""
        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        # Empty patch will fail validation

        entry = audit_log.record_rejection(
            patch,
            reason="Validation failed: empty patch",
            validation_errors=["Patch contains no operations"],
        )

        assert entry.action == AuditAction.REJECTED
        assert entry.success is False
        assert entry.error == "Validation failed: empty patch"
        assert "Patch contains no operations" in entry.validation_errors

    def test_record_version_mismatch(self, audit_log, applier, state_store):
        """Test recording version mismatch failure."""
        # Increment version to create mismatch
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
        entry = audit_log.record(patch, result)

        assert entry.action == AuditAction.REJECTED
        assert entry.success is False
        assert "version" in entry.error.lower()

    def test_get_entries(self, audit_log, applier, state_store):
        """Test retrieving audit entries."""
        # Create multiple patches
        for i in range(3):
            patch = Patch(
                session_id="session-001",
                agent_id=f"agent_{i}",
                base_state_version=state_store.get_version(),
            )
            patch.add_operation(
                op=OperationType.ADD_OBSERVATION,
                target="192.168.1.1",
                payload={"tool": "nmap", "action": f"scan_{i}"},
            )
            result = applier.apply(patch)
            audit_log.record(patch, result)

        entries = audit_log.get_entries()

        assert len(entries) == 3
        # Should be newest first
        assert entries[0].agent_id == "agent_2"

    def test_get_entries_with_limit(self, audit_log, applier, state_store):
        """Test retrieving limited audit entries."""
        for i in range(5):
            patch = Patch(
                session_id="session-001",
                agent_id="agent",
                base_state_version=state_store.get_version(),
            )
            patch.add_operation(
                op=OperationType.ADD_OBSERVATION,
                target="192.168.1.1",
                payload={"tool": "nmap", "action": f"scan_{i}"},
            )
            result = applier.apply(patch)
            audit_log.record(patch, result)

        entries = audit_log.get_entries(limit=3)

        assert len(entries) == 3

    def test_get_entries_filter_by_session(self, audit_log, applier, state_store):
        """Test filtering entries by session."""
        for session in ["session-001", "session-002", "session-001"]:
            patch = Patch(
                session_id=session,
                agent_id="agent",
                base_state_version=state_store.get_version(),
            )
            patch.add_operation(
                op=OperationType.ADD_OBSERVATION,
                target="192.168.1.1",
                payload={"tool": "nmap", "action": "scan"},
            )
            result = applier.apply(patch)
            audit_log.record(patch, result)

        entries = audit_log.get_entries(session_id="session-001")

        assert len(entries) == 2

    def test_get_entries_filter_by_agent(self, audit_log, applier, state_store):
        """Test filtering entries by agent."""
        for agent in ["agent_a", "agent_b", "agent_a"]:
            patch = Patch(
                session_id="session-001",
                agent_id=agent,
                base_state_version=state_store.get_version(),
            )
            patch.add_operation(
                op=OperationType.ADD_OBSERVATION,
                target="192.168.1.1",
                payload={"tool": "nmap", "action": "scan"},
            )
            result = applier.apply(patch)
            audit_log.record(patch, result)

        entries = audit_log.get_entries(agent_id="agent_a")

        assert len(entries) == 2

    def test_get_entries_for_patch(self, audit_log, applier, state_store):
        """Test getting entries for specific patch."""
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
        audit_log.record(patch, result)

        entries = audit_log.get_entries_for_patch(patch.patch_id)

        assert len(entries) == 1
        assert entries[0].patch_id == patch.patch_id

    def test_get_agent_activity(self, audit_log, applier, state_store):
        """Test getting agent activity summary."""
        # Create successful patches
        for i in range(3):
            patch = Patch(
                session_id="session-001",
                agent_id="recon_agent",
                base_state_version=state_store.get_version(),
            )
            patch.add_operation(
                op=OperationType.ADD_OBSERVATION,
                target="192.168.1.1",
                payload={"tool": "nmap", "action": f"scan_{i}"},
            )
            result = applier.apply(patch)
            audit_log.record(patch, result)

        # Create a failed patch (version mismatch)
        state_store.increment_version("test")
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=0,  # Old version
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan"},
        )
        result = applier.apply(patch)
        audit_log.record(patch, result)

        activity = audit_log.get_agent_activity("recon_agent")

        assert activity["agent_id"] == "recon_agent"
        assert activity["total_patches"] == 4
        assert activity["successful"] == 3
        assert activity["failed"] == 1
        assert activity["success_rate"] == 0.75

    def test_count_entries(self, audit_log, applier, state_store):
        """Test counting audit entries."""
        for i in range(5):
            patch = Patch(
                session_id="session-001",
                agent_id="agent",
                base_state_version=state_store.get_version(),
            )
            patch.add_operation(
                op=OperationType.ADD_OBSERVATION,
                target="192.168.1.1",
                payload={"tool": "nmap", "action": f"scan_{i}"},
            )
            result = applier.apply(patch)
            audit_log.record(patch, result)

        assert audit_log.count_entries() == 5

    def test_audit_entry_to_dict(self, audit_log, applier, state_store):
        """Test AuditEntry serialization."""
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
        entry = audit_log.record(patch, result)

        data = entry.to_dict()

        assert data["patch_id"] == patch.patch_id
        assert data["action"] == "applied"
        assert data["success"] is True
        assert "timestamp" in data

    def test_audit_entry_from_dict(self):
        """Test AuditEntry deserialization."""
        data = {
            "timestamp": "2024-01-15T10:30:00Z",
            "patch_id": "patch-123",
            "session_id": "session-001",
            "agent_id": "agent",
            "action": "applied",
            "base_version": 0,
            "new_version": 1,
            "operations_count": 2,
            "operations_applied": 2,
            "success": True,
            "error": None,
            "validation_errors": [],
            "affected_targets": ["192.168.1.1"],
            "operation_types": ["add_observation", "add_observation"],
        }

        entry = AuditEntry.from_dict(data)

        assert entry.patch_id == "patch-123"
        assert entry.action == AuditAction.APPLIED
        assert entry.success is True
        assert entry.operations_count == 2

    def test_clear_audit_log(self, audit_log, applier, state_store):
        """Test clearing audit log."""
        # Add some entries
        for i in range(3):
            patch = Patch(
                session_id="session-001",
                agent_id="agent",
                base_state_version=state_store.get_version(),
            )
            patch.add_operation(
                op=OperationType.ADD_OBSERVATION,
                target="192.168.1.1",
                payload={"tool": "nmap", "action": f"scan_{i}"},
            )
            result = applier.apply(patch)
            audit_log.record(patch, result)

        assert audit_log.count_entries() == 3

        audit_log.clear()

        assert audit_log.count_entries() == 0
