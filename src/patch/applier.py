"""
Patch Applier for PentestAgent.

Applies validated patches to state atomically with rollback support.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .patch import Patch, PatchOperation
from .operations import OperationType
from .validator import PatchValidator, ValidationResult

if TYPE_CHECKING:
    from ..storage.state_store import StateStore
    from ..storage.evidence_ledger import EvidenceLedger
    from ..schemas.scope import Scope


class ApplyError(Exception):
    """Raised when patch application fails."""
    pass


class RollbackError(Exception):
    """Raised when rollback fails."""
    pass


@dataclass
class OperationResult:
    """Result of applying a single operation."""
    success: bool
    operation_index: int
    operation_type: str
    target: str
    object_id: Optional[str] = None
    error: Optional[str] = None
    created_data: Optional[Dict[str, Any]] = None


@dataclass
class ApplyResult:
    """Result of applying a patch."""
    success: bool
    patch_id: str
    new_state_version: Optional[int] = None
    operations_applied: int = 0
    operation_results: List[OperationResult] = dataclass_field(default_factory=list)
    error: Optional[str] = None
    validation_errors: List[str] = dataclass_field(default_factory=list)
    rolled_back: bool = False
    applied_at: datetime = dataclass_field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "success": self.success,
            "patch_id": self.patch_id,
            "new_state_version": self.new_state_version,
            "operations_applied": self.operations_applied,
            "operation_results": [
                {
                    "success": r.success,
                    "operation_index": r.operation_index,
                    "operation_type": r.operation_type,
                    "target": r.target,
                    "object_id": r.object_id,
                    "error": r.error,
                }
                for r in self.operation_results
            ],
            "error": self.error,
            "validation_errors": self.validation_errors,
            "rolled_back": self.rolled_back,
            "applied_at": self.applied_at.isoformat() + "Z",
        }


class PatchApplier:
    """
    Applies patches to state atomically.

    Features:
    - Validation before application
    - Atomic all-or-nothing application
    - Rollback on failure
    - Version increment on success
    """

    # File mappings for each operation type
    JSONL_FILES = {
        OperationType.ADD_OBSERVATION: "observations.jsonl",
        OperationType.ADD_VULN_CANDIDATE: "vuln_candidates.jsonl",
        OperationType.ADD_EXPLOIT_CANDIDATE: "exploit_candidates.jsonl",
        OperationType.RECORD_EXECUTION_RESULT: "execution_results.jsonl",
        OperationType.ADD_FINDING_CANDIDATE: "finding_candidates.jsonl",
        OperationType.ADD_DECISION_TRACE: "decision_traces.jsonl",
    }

    JSON_FILES = {
        OperationType.UPDATE_TARGET_PROFILE: "target_profile.json",
        OperationType.PROPOSE_EXECUTION_PLAN: "execution_plans.json",
    }

    def __init__(
        self,
        state_store: "StateStore",
        evidence_ledger: "EvidenceLedger",
        scope: Optional["Scope"] = None,
        existing_ids: Optional[set] = None,
        validate_before_apply: bool = True,
    ):
        """
        Initialize applier.

        Args:
            state_store: State store for state files.
            evidence_ledger: Evidence ledger for evidence storage.
            scope: Scope for validation (optional).
            existing_ids: Set of existing object IDs.
            validate_before_apply: Whether to validate before applying.
        """
        self.state_store = state_store
        self.evidence_ledger = evidence_ledger
        self.scope = scope
        self.existing_ids = existing_ids or set()
        self.validate_before_apply = validate_before_apply

    def apply(self, patch: Patch) -> ApplyResult:
        """
        Apply a patch atomically.

        Args:
            patch: The patch to apply.

        Returns:
            ApplyResult with success status and details.
        """
        result = ApplyResult(
            success=False,
            patch_id=patch.patch_id,
        )

        # Validate if required
        if self.validate_before_apply:
            validator = PatchValidator(
                state_store=self.state_store,
                evidence_ledger=self.evidence_ledger,
                scope=self.scope,
                existing_ids=self.existing_ids,
            )
            validation = validator.validate(patch)

            if not validation.valid:
                result.validation_errors = validation.error_messages()
                result.error = "Validation failed: " + "; ".join(result.validation_errors)
                return result

        # Store rollback data
        rollback_data = self._capture_state_for_rollback(patch)

        try:
            # Apply each operation
            for idx, operation in enumerate(patch.operations):
                op_result = self._apply_operation(patch, operation, idx)
                result.operation_results.append(op_result)

                if not op_result.success:
                    raise ApplyError(
                        f"Operation {idx} failed: {op_result.error}"
                    )

                result.operations_applied += 1

            # Increment state version
            new_version = self.state_store.increment_version(
                reason=f"Patch {patch.patch_id} applied ({result.operations_applied} operations)",
                actor=patch.agent_id,
            )
            result.new_state_version = new_version
            result.success = True

        except ApplyError as e:
            result.error = str(e)
            # Attempt rollback
            try:
                self._rollback(rollback_data)
                result.rolled_back = True
            except RollbackError as re:
                result.error = f"{result.error}; Rollback failed: {re}"

        except Exception as e:
            result.error = f"Unexpected error: {e}"
            # Attempt rollback
            try:
                self._rollback(rollback_data)
                result.rolled_back = True
            except RollbackError as re:
                result.error = f"{result.error}; Rollback failed: {re}"

        return result

    def _apply_operation(
        self,
        patch: Patch,
        operation: PatchOperation,
        index: int,
    ) -> OperationResult:
        """Apply a single operation."""
        op_type = (
            OperationType(operation.op)
            if isinstance(operation.op, str)
            else operation.op
        )

        result = OperationResult(
            success=False,
            operation_index=index,
            operation_type=op_type.value,
            target=operation.target,
        )

        try:
            # Dispatch to specific handler
            if op_type == OperationType.ADD_EVIDENCE:
                result = self._apply_add_evidence(patch, operation, index)

            elif op_type == OperationType.ADD_OBSERVATION:
                result = self._apply_add_jsonl(
                    patch, operation, index, "observations.jsonl"
                )

            elif op_type == OperationType.UPDATE_TARGET_PROFILE:
                result = self._apply_update_target_profile(patch, operation, index)

            elif op_type == OperationType.ADD_VULN_CANDIDATE:
                result = self._apply_add_jsonl(
                    patch, operation, index, "vuln_candidates.jsonl"
                )

            elif op_type == OperationType.ADD_EXPLOIT_CANDIDATE:
                result = self._apply_add_jsonl(
                    patch, operation, index, "exploit_candidates.jsonl"
                )

            elif op_type == OperationType.PROPOSE_EXECUTION_PLAN:
                result = self._apply_propose_execution_plan(patch, operation, index)

            elif op_type == OperationType.RECORD_EXECUTION_RESULT:
                result = self._apply_add_jsonl(
                    patch, operation, index, "execution_results.jsonl"
                )

            elif op_type == OperationType.ADD_FINDING_CANDIDATE:
                result = self._apply_add_jsonl(
                    patch, operation, index, "finding_candidates.jsonl"
                )

            elif op_type == OperationType.PROMOTE_FINDING_CANDIDATE:
                result = self._apply_promote_finding(patch, operation, index)

            elif op_type == OperationType.ADD_DECISION_TRACE:
                result = self._apply_add_jsonl(
                    patch, operation, index, "decision_traces.jsonl"
                )

            else:
                result.error = f"Unsupported operation type: {op_type}"

        except Exception as e:
            result.error = str(e)

        return result

    def _apply_add_evidence(
        self,
        patch: Patch,
        operation: PatchOperation,
        index: int,
    ) -> OperationResult:
        """Apply add_evidence operation."""
        result = OperationResult(
            success=False,
            operation_index=index,
            operation_type=OperationType.ADD_EVIDENCE.value,
            target=operation.target,
        )

        payload = operation.payload
        data = payload.get("data", b"")
        if isinstance(data, str):
            data = data.encode("utf-8")

        meta = self.evidence_ledger.store(
            data=data,
            source_tool=payload.get("source_tool", "unknown"),
            extension=payload.get("extension", "bin"),
            query_params=payload.get("query_params"),
            response_code=payload.get("response_code"),
            mime_type=payload.get("mime_type"),
            additional_meta=payload.get("additional_meta"),
        )

        result.success = True
        result.object_id = meta["evidence_id"]
        result.created_data = meta

        # Add to existing IDs
        self.existing_ids.add(meta["evidence_id"])

        return result

    def _apply_add_jsonl(
        self,
        patch: Patch,
        operation: PatchOperation,
        index: int,
        filename: str,
    ) -> OperationResult:
        """Apply operation that adds to a JSONL file."""
        op_type = (
            OperationType(operation.op)
            if isinstance(operation.op, str)
            else operation.op
        )

        result = OperationResult(
            success=False,
            operation_index=index,
            operation_type=op_type.value,
            target=operation.target,
        )

        # Build record from payload
        record = dict(operation.payload)

        # Add metadata
        record["session_id"] = patch.session_id
        record["created_by"] = patch.agent_id
        record["scope_tag"] = patch.scope_tag or operation.target
        record["created_at"] = datetime.utcnow().isoformat() + "Z"

        # Generate ID if not provided
        if "id" not in record:
            import uuid
            record["id"] = str(uuid.uuid4())

        # Append to JSONL file
        self.state_store.append_jsonl(filename, record)

        result.success = True
        result.object_id = record["id"]
        result.created_data = record

        # Add to existing IDs
        self.existing_ids.add(record["id"])

        return result

    def _apply_update_target_profile(
        self,
        patch: Patch,
        operation: PatchOperation,
        index: int,
    ) -> OperationResult:
        """Apply update_target_profile operation."""
        result = OperationResult(
            success=False,
            operation_index=index,
            operation_type=OperationType.UPDATE_TARGET_PROFILE.value,
            target=operation.target,
        )

        filename = "target_profile.json"

        # Load existing or create new
        try:
            existing = self.state_store.read_json(filename)
        except FileNotFoundError:
            existing = {
                "session_id": patch.session_id,
                "created_by": patch.agent_id,
                "scope_tag": patch.scope_tag or operation.target,
                "hosts": [],
                "technologies": [],
            }

        # Merge payload into existing
        updated = self._deep_merge(existing, operation.payload)

        # Update metadata
        updated["updated_at"] = datetime.utcnow().isoformat() + "Z"
        updated["updated_by"] = patch.agent_id

        # Write back
        self.state_store.write_json(filename, updated)

        result.success = True
        result.object_id = updated.get("id")
        result.created_data = updated

        return result

    def _apply_propose_execution_plan(
        self,
        patch: Patch,
        operation: PatchOperation,
        index: int,
    ) -> OperationResult:
        """Apply propose_execution_plan operation."""
        result = OperationResult(
            success=False,
            operation_index=index,
            operation_type=OperationType.PROPOSE_EXECUTION_PLAN.value,
            target=operation.target,
        )

        filename = "execution_plans.json"

        # Load existing plans or create new
        try:
            data = self.state_store.read_json(filename)
            plans = data.get("plans", [])
        except FileNotFoundError:
            plans = []

        # Build plan record
        plan = dict(operation.payload)
        plan["session_id"] = patch.session_id
        plan["created_by"] = patch.agent_id
        plan["scope_tag"] = patch.scope_tag or operation.target
        plan["created_at"] = datetime.utcnow().isoformat() + "Z"
        plan["approved"] = False
        plan["requires_approval"] = operation.requires_approval

        # Generate ID if not provided
        if "id" not in plan:
            import uuid
            plan["id"] = f"plan-{uuid.uuid4()}"

        plans.append(plan)

        # Write back
        self.state_store.write_json(filename, {"plans": plans})

        result.success = True
        result.object_id = plan["id"]
        result.created_data = plan

        # Add to existing IDs
        self.existing_ids.add(plan["id"])

        return result

    def _apply_promote_finding(
        self,
        patch: Patch,
        operation: PatchOperation,
        index: int,
    ) -> OperationResult:
        """Apply promote_finding_candidate operation."""
        result = OperationResult(
            success=False,
            operation_index=index,
            operation_type=OperationType.PROMOTE_FINDING_CANDIDATE.value,
            target=operation.target,
        )

        finding_id = operation.payload.get("finding_id")
        promoted_by = operation.payload.get("promoted_by")

        # Read all findings
        filename = "finding_candidates.jsonl"
        findings = self.state_store.read_jsonl(filename)

        # Find and update the finding
        found = False
        updated_findings = []

        for finding in findings:
            if finding.get("id") == finding_id:
                finding["promoted"] = True
                finding["promoted_by"] = promoted_by
                finding["promoted_at"] = datetime.utcnow().isoformat() + "Z"
                found = True
                result.object_id = finding_id
                result.created_data = finding
            updated_findings.append(finding)

        if not found:
            result.error = f"Finding not found: {finding_id}"
            return result

        # Rewrite the file (not ideal but works for now)
        # Clear and rewrite
        file_path = self.state_store.state_dir / filename
        file_path.write_text("")
        for finding in updated_findings:
            self.state_store.append_jsonl(filename, finding)

        result.success = True
        return result

    def _deep_merge(
        self,
        base: Dict[str, Any],
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Deep merge updates into base dict."""
        result = copy.deepcopy(base)

        for key, value in updates.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self._deep_merge(result[key], value)
            elif (
                key in result
                and isinstance(result[key], list)
                and isinstance(value, list)
            ):
                # For lists, extend rather than replace
                result[key].extend(value)
            else:
                result[key] = value

        return result

    def _capture_state_for_rollback(self, patch: Patch) -> Dict[str, Any]:
        """Capture current state for potential rollback."""
        rollback_data = {
            "state_version": self.state_store.get_version(),
            "files": {},
        }

        # Capture affected files
        affected_files = set()
        for op in patch.operations:
            op_type = (
                OperationType(op.op)
                if isinstance(op.op, str)
                else op.op
            )

            if op_type in self.JSONL_FILES:
                affected_files.add(self.JSONL_FILES[op_type])
            elif op_type in self.JSON_FILES:
                affected_files.add(self.JSON_FILES[op_type])

        # Capture file contents
        for filename in affected_files:
            try:
                if filename.endswith(".jsonl"):
                    rollback_data["files"][filename] = self.state_store.read_jsonl(filename)
                else:
                    rollback_data["files"][filename] = self.state_store.read_json(filename)
            except FileNotFoundError:
                rollback_data["files"][filename] = None

        return rollback_data

    def _rollback(self, rollback_data: Dict[str, Any]) -> None:
        """Rollback to previous state."""
        try:
            for filename, content in rollback_data["files"].items():
                file_path = self.state_store.state_dir / filename

                if content is None:
                    # File didn't exist before - remove if created
                    if file_path.exists():
                        file_path.unlink()
                elif filename.endswith(".jsonl"):
                    # Rewrite JSONL file
                    file_path.write_text("")
                    for record in content:
                        self.state_store.append_jsonl(filename, record)
                else:
                    # Rewrite JSON file
                    self.state_store.write_json(filename, content)

        except Exception as e:
            raise RollbackError(f"Failed to rollback: {e}")
