"""Tests for Patch and PatchOperation classes."""

import pytest
from datetime import datetime

from src.patch.patch import Patch, PatchOperation
from src.patch.operations import OperationType


class TestPatchOperation:
    """Tests for PatchOperation."""

    def test_create_operation(self):
        """Test creating a patch operation."""
        op = PatchOperation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "port_scan"},
        )

        assert op.op == OperationType.ADD_OBSERVATION.value
        assert op.target == "192.168.1.1"
        assert op.payload["tool"] == "nmap"
        assert op.requires_approval is False

    def test_operation_with_approval(self):
        """Test operation that requires approval."""
        op = PatchOperation(
            op=OperationType.PROPOSE_EXECUTION_PLAN,
            target="plan-001",
            payload={"title": "Test Plan", "description": "Test", "target": "192.168.1.1"},
            requires_approval=True,
        )

        assert op.requires_approval is True

    def test_operation_empty_target_fails(self):
        """Test that empty target raises error."""
        with pytest.raises(ValueError, match="target cannot be empty"):
            PatchOperation(
                op=OperationType.ADD_OBSERVATION,
                target="",
                payload={},
            )

    def test_operation_from_string_op(self):
        """Test creating operation with string op type."""
        op = PatchOperation(
            op="add_observation",
            target="192.168.1.1",
            payload={},
        )

        assert op.op == "add_observation"


class TestPatch:
    """Tests for Patch."""

    def test_create_patch(self):
        """Test creating a patch."""
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=0,
        )

        assert patch.session_id == "session-001"
        assert patch.agent_id == "recon_agent"
        assert patch.base_state_version == 0
        assert patch.patch_id.startswith("patch-")
        assert patch.is_empty() is True

    def test_add_operation(self):
        """Test adding operations to a patch."""
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=0,
        )

        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "port_scan"},
        )

        assert patch.operation_count() == 1
        assert patch.is_empty() is False

    def test_patch_requires_approval(self):
        """Test checking if patch requires approval."""
        patch = Patch(
            session_id="session-001",
            agent_id="planner_agent",
            base_state_version=0,
        )

        # No approval needed initially
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={},
        )
        assert patch.requires_approval() is False

        # Add operation that requires approval
        patch.add_operation(
            op=OperationType.PROPOSE_EXECUTION_PLAN,
            target="plan-001",
            payload={},
            requires_approval=True,
        )
        assert patch.requires_approval() is True

    def test_get_affected_targets(self):
        """Test getting affected targets."""
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=0,
        )

        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={},
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.2",
            payload={},
        )
        patch.add_operation(
            op=OperationType.UPDATE_TARGET_PROFILE,
            target="192.168.1.1",  # Duplicate
            payload={},
        )

        targets = patch.get_affected_targets()
        assert len(targets) == 2
        assert "192.168.1.1" in targets
        assert "192.168.1.2" in targets

    def test_patch_to_dict(self):
        """Test converting patch to dictionary."""
        patch = Patch(
            session_id="session-001",
            agent_id="recon_agent",
            base_state_version=5,
            description="Test patch",
        )

        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap"},
        )

        data = patch.to_dict()

        assert data["session_id"] == "session-001"
        assert data["agent_id"] == "recon_agent"
        assert data["base_state_version"] == 5
        assert data["description"] == "Test patch"
        assert len(data["operations"]) == 1
        assert data["operations"][0]["op"] == "add_observation"

    def test_patch_from_dict(self):
        """Test creating patch from dictionary."""
        data = {
            "patch_id": "patch-123",
            "session_id": "session-001",
            "agent_id": "recon_agent",
            "base_state_version": 5,
            "operations": [
                {
                    "op": "add_observation",
                    "target": "192.168.1.1",
                    "payload": {"tool": "nmap"},
                    "requires_approval": False,
                }
            ],
            "description": "Test patch",
        }

        patch = Patch.from_dict(data)

        assert patch.patch_id == "patch-123"
        assert patch.session_id == "session-001"
        assert patch.base_state_version == 5
        assert patch.operation_count() == 1

    def test_empty_session_id_fails(self):
        """Test that empty session_id raises error."""
        with pytest.raises(ValueError, match="session_id cannot be empty"):
            Patch(
                session_id="",
                agent_id="agent",
                base_state_version=0,
            )

    def test_empty_agent_id_fails(self):
        """Test that empty agent_id raises error."""
        with pytest.raises(ValueError, match="agent_id cannot be empty"):
            Patch(
                session_id="session",
                agent_id="",
                base_state_version=0,
            )
