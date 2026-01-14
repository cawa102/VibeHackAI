"""Tests for PatchValidator."""

import pytest
import tempfile
from pathlib import Path

from src.patch.patch import Patch
from src.patch.operations import OperationType
from src.patch.validator import (
    PatchValidator,
    ValidationErrorType,
    ValidationResult,
)
from src.storage.state_store import StateStore
from src.storage.evidence_ledger import EvidenceLedger
from src.schemas.scope import Scope, TargetSpec, TargetType


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
def scope():
    """Create a test scope."""
    return Scope(
        session_id="test-session",
        created_by="human",
        scope_tag="test",
        targets=[
            TargetSpec(value="192.168.1.1", type=TargetType.IP),
            TargetSpec(value="192.168.1.0/24", type=TargetType.CIDR),
            TargetSpec(value="example.com", type=TargetType.DOMAIN),
        ],
    )


class TestPatchValidator:
    """Tests for PatchValidator."""

    def test_validate_empty_patch(self, state_store, evidence_ledger):
        """Test validation fails for empty patch."""
        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=0,
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is False
        assert any(e.error_type == ValidationErrorType.EMPTY_PATCH for e in result.errors)

    def test_validate_version_mismatch(self, state_store, evidence_ledger):
        """Test validation fails when version doesn't match."""
        # Increment state version
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

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is False
        assert any(e.error_type == ValidationErrorType.VERSION_MISMATCH for e in result.errors)

    def test_validate_version_match(self, state_store, evidence_ledger):
        """Test validation passes when version matches."""
        current_version = state_store.get_version()

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=current_version,
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan"},
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is True

    def test_validate_missing_required_fields(self, state_store, evidence_ledger):
        """Test validation fails for missing required fields."""
        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={},  # Missing 'tool' and 'action'
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is False
        assert any(e.error_type == ValidationErrorType.MISSING_FIELD for e in result.errors)

    def test_validate_evidence_not_found(self, state_store, evidence_ledger):
        """Test validation fails when evidence doesn't exist."""
        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={
                "tool": "nmap",
                "action": "scan",
                "evidence_ids": ["ev-nonexistent"],
            },
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is False
        assert any(e.error_type == ValidationErrorType.EVIDENCE_NOT_FOUND for e in result.errors)

    def test_validate_evidence_exists(self, state_store, evidence_ledger):
        """Test validation passes when evidence exists."""
        # Store some evidence
        meta = evidence_ledger.store(
            data=b"test data",
            source_tool="test",
        )

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={
                "tool": "nmap",
                "action": "scan",
                "evidence_ids": [meta["evidence_id"]],
            },
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is True

    def test_validate_approval_required(self, state_store, evidence_ledger):
        """Test validation fails when approval required but not set."""
        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.PROPOSE_EXECUTION_PLAN,
            target="plan-001",
            payload={"title": "Test", "description": "Test", "target": "192.168.1.1"},
            requires_approval=False,  # Should be True
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is False
        assert any(e.error_type == ValidationErrorType.APPROVAL_REQUIRED for e in result.errors)

    def test_validate_approval_set(self, state_store, evidence_ledger):
        """Test validation passes when approval is properly set."""
        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.PROPOSE_EXECUTION_PLAN,
            target="plan-001",
            payload={"title": "Test", "description": "Test", "target": "192.168.1.1"},
            requires_approval=True,
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is True

    def test_validate_duplicate_object(self, state_store, evidence_ledger):
        """Test validation fails for duplicate object IDs."""
        existing_ids = {"existing-id-001"}

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={
                "id": "existing-id-001",  # Already exists
                "tool": "nmap",
                "action": "scan",
            },
        )

        validator = PatchValidator(state_store, evidence_ledger, existing_ids=existing_ids)
        result = validator.validate(patch)

        assert result.valid is False
        assert any(e.error_type == ValidationErrorType.DUPLICATE_OBJECT for e in result.errors)

    def test_validate_finding_high_severity_needs_evidence(self, state_store, evidence_ledger):
        """Test that high severity findings need 2+ evidence items."""
        # Store one evidence
        meta = evidence_ledger.store(data=b"test", source_tool="test")

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.ADD_FINDING_CANDIDATE,
            target="finding-001",
            payload={
                "title": "Critical Finding",
                "severity": "critical",
                "description": "Critical issue",
                "impact": "High",
                "affected_component": "server",
                "remediation": "Fix it",
                "evidence_ids": [meta["evidence_id"]],  # Only 1
            },
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is False
        # Should have error about insufficient evidence
        assert any("2 evidence" in e.message for e in result.errors)

    def test_validate_finding_high_severity_with_enough_evidence(self, state_store, evidence_ledger):
        """Test high severity finding passes with 2+ evidence."""
        # Store two evidence items
        meta1 = evidence_ledger.store(data=b"test1", source_tool="test")
        meta2 = evidence_ledger.store(data=b"test2", source_tool="test")

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
        )
        patch.add_operation(
            op=OperationType.ADD_FINDING_CANDIDATE,
            target="finding-001",
            payload={
                "title": "Critical Finding",
                "severity": "critical",
                "description": "Critical issue",
                "impact": "High",
                "affected_component": "server",
                "remediation": "Fix it",
                "evidence_ids": [meta1["evidence_id"], meta2["evidence_id"]],
            },
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is True

    def test_validate_with_scope(self, state_store, evidence_ledger, scope):
        """Test validation with scope checking."""
        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=state_store.get_version(),
            scope_tag="test",
        )
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"tool": "nmap", "action": "scan"},
        )

        validator = PatchValidator(state_store, evidence_ledger, scope=scope)
        result = validator.validate(patch)

        assert result.valid is True

    def test_validate_multiple_errors(self, state_store, evidence_ledger):
        """Test validation returns multiple errors."""
        # Increment version to create mismatch
        state_store.increment_version("test")

        patch = Patch(
            session_id="session-001",
            agent_id="agent",
            base_state_version=0,  # Old version
        )
        # Add operation missing required fields
        patch.add_operation(
            op=OperationType.ADD_OBSERVATION,
            target="192.168.1.1",
            payload={"evidence_ids": ["ev-nonexistent"]},  # Missing fields, bad evidence
        )

        validator = PatchValidator(state_store, evidence_ledger)
        result = validator.validate(patch)

        assert result.valid is False
        assert len(result.errors) >= 2  # At least version mismatch and missing fields
