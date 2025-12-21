"""
Patch Validator for PentestAgent.

Validates patches before application to ensure safety and correctness.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, TYPE_CHECKING

from .patch import Patch, PatchOperation
from .operations import (
    OperationType,
    APPROVAL_REQUIRED_OPERATIONS,
    OPERATION_REQUIRED_FIELDS,
)

if TYPE_CHECKING:
    from ..storage.state_store import StateStore
    from ..storage.evidence_ledger import EvidenceLedger
    from ..schemas.scope import Scope


class ValidationErrorType(str, Enum):
    """Types of validation errors."""
    VERSION_MISMATCH = "version_mismatch"
    SCOPE_VIOLATION = "scope_violation"
    MISSING_FIELD = "missing_field"
    EVIDENCE_NOT_FOUND = "evidence_not_found"
    APPROVAL_REQUIRED = "approval_required"
    DUPLICATE_OBJECT = "duplicate_object"
    INVALID_OPERATION = "invalid_operation"
    INVALID_PAYLOAD = "invalid_payload"
    EMPTY_PATCH = "empty_patch"
    OBJECT_NOT_FOUND = "object_not_found"


@dataclass
class ValidationError:
    """A single validation error."""
    error_type: ValidationErrorType
    message: str
    operation_index: Optional[int] = None
    field_name: Optional[str] = None
    details: Dict[str, Any] = dataclass_field(default_factory=dict)


@dataclass
class ValidationResult:
    """Result of patch validation."""
    valid: bool
    errors: List[ValidationError] = dataclass_field(default_factory=list)
    warnings: List[str] = dataclass_field(default_factory=list)

    def add_error(
        self,
        error_type: ValidationErrorType,
        message: str,
        operation_index: Optional[int] = None,
        field_name: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Add a validation error."""
        self.valid = False
        self.errors.append(ValidationError(
            error_type=error_type,
            message=message,
            operation_index=operation_index,
            field_name=field_name,
            details=details or {},
        ))

    def add_warning(self, message: str) -> None:
        """Add a validation warning."""
        self.warnings.append(message)

    def error_messages(self) -> List[str]:
        """Get list of error messages."""
        return [e.message for e in self.errors]


class PatchValidator:
    """
    Validates patches before application.

    Performs the following validations:
    1. Version validation (optimistic locking)
    2. Scope validation
    3. Required field validation
    4. Evidence existence validation
    5. Approval requirement validation
    6. Duplicate object validation
    """

    def __init__(
        self,
        state_store: "StateStore",
        evidence_ledger: "EvidenceLedger",
        scope: Optional["Scope"] = None,
        existing_ids: Optional[Set[str]] = None,
    ):
        """
        Initialize validator.

        Args:
            state_store: State store for version checking.
            evidence_ledger: Evidence ledger for evidence validation.
            scope: Scope for scope validation (optional).
            existing_ids: Set of existing object IDs for duplicate checking.
        """
        self.state_store = state_store
        self.evidence_ledger = evidence_ledger
        self.scope = scope
        self.existing_ids = existing_ids or set()

    def validate(self, patch: Patch) -> ValidationResult:
        """
        Validate a patch.

        Args:
            patch: The patch to validate.

        Returns:
            ValidationResult with errors if any.
        """
        result = ValidationResult(valid=True)

        # Check for empty patch
        if patch.is_empty():
            result.add_error(
                ValidationErrorType.EMPTY_PATCH,
                "Patch contains no operations",
            )
            return result

        # 1. Version validation
        self._validate_version(patch, result)

        # 2. Validate each operation
        for idx, operation in enumerate(patch.operations):
            self._validate_operation(patch, operation, idx, result)

        return result

    def _validate_version(self, patch: Patch, result: ValidationResult) -> None:
        """Validate state version for optimistic locking."""
        current_version = self.state_store.get_version()
        if patch.base_state_version != current_version:
            result.add_error(
                ValidationErrorType.VERSION_MISMATCH,
                f"State version conflict: patch based on version "
                f"{patch.base_state_version}, current is {current_version}",
                details={
                    "expected_version": patch.base_state_version,
                    "current_version": current_version,
                },
            )

    def _validate_operation(
        self,
        patch: Patch,
        operation: PatchOperation,
        index: int,
        result: ValidationResult,
    ) -> None:
        """Validate a single operation."""
        # Get operation type
        try:
            op_type = (
                OperationType(operation.op)
                if isinstance(operation.op, str)
                else operation.op
            )
        except ValueError:
            result.add_error(
                ValidationErrorType.INVALID_OPERATION,
                f"Unknown operation type: {operation.op}",
                operation_index=index,
            )
            return

        # Validate required fields
        self._validate_required_fields(op_type, operation, index, result)

        # Validate scope
        self._validate_scope(patch, operation, index, result)

        # Validate evidence references
        self._validate_evidence_references(operation, index, result)

        # Validate approval requirements
        self._validate_approval_requirements(op_type, operation, index, result)

        # Validate duplicates
        self._validate_duplicates(operation, index, result)

        # Operation-specific validation
        self._validate_operation_specific(op_type, operation, index, result)

    def _validate_required_fields(
        self,
        op_type: OperationType,
        operation: PatchOperation,
        index: int,
        result: ValidationResult,
    ) -> None:
        """Validate required fields in operation payload."""
        required_fields = OPERATION_REQUIRED_FIELDS.get(op_type, [])

        for field_name in required_fields:
            if field_name not in operation.payload:
                result.add_error(
                    ValidationErrorType.MISSING_FIELD,
                    f"Missing required field '{field_name}' for operation {op_type.value}",
                    operation_index=index,
                    field_name=field_name,
                )

    def _validate_scope(
        self,
        patch: Patch,
        operation: PatchOperation,
        index: int,
        result: ValidationResult,
    ) -> None:
        """Validate operation is within scope."""
        if self.scope is None:
            return

        # Check if scope is expired
        if self.scope.is_expired():
            result.add_error(
                ValidationErrorType.SCOPE_VIOLATION,
                "Scope has expired",
                operation_index=index,
            )
            return

        # Check target against scope if it looks like an IP/domain
        target = operation.target
        payload = operation.payload

        # Check for target in payload
        target_value = payload.get("target") or payload.get("affected_component")
        if target_value:
            # Simple check - could be enhanced with IP/domain parsing
            if not self._is_target_in_scope(target_value):
                result.add_warning(
                    f"Target '{target_value}' may be outside scope - verify manually"
                )

    def _is_target_in_scope(self, target: str) -> bool:
        """Check if a target value is within scope."""
        if self.scope is None:
            return True

        # Check against all scope targets
        for scope_target in self.scope.targets:
            if scope_target.value == target:
                return True
            # Check CIDR containment for IPs
            if self._is_ip_like(target):
                if self.scope._ip_in_cidr(target, scope_target.value):
                    return True

        return False

    def _is_ip_like(self, value: str) -> bool:
        """Check if a value looks like an IP address."""
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _validate_evidence_references(
        self,
        operation: PatchOperation,
        index: int,
        result: ValidationResult,
    ) -> None:
        """Validate that referenced evidence IDs exist."""
        evidence_ids = operation.payload.get("evidence_ids", [])
        if not evidence_ids:
            return

        for evidence_id in evidence_ids:
            if not self.evidence_ledger.exists(evidence_id):
                result.add_error(
                    ValidationErrorType.EVIDENCE_NOT_FOUND,
                    f"Evidence not found: {evidence_id}",
                    operation_index=index,
                    details={"evidence_id": evidence_id},
                )

    def _validate_approval_requirements(
        self,
        op_type: OperationType,
        operation: PatchOperation,
        index: int,
        result: ValidationResult,
    ) -> None:
        """Validate approval requirements for dangerous operations."""
        if op_type in APPROVAL_REQUIRED_OPERATIONS:
            if not operation.requires_approval:
                result.add_error(
                    ValidationErrorType.APPROVAL_REQUIRED,
                    f"Operation {op_type.value} requires approval flag to be set",
                    operation_index=index,
                )

    def _validate_duplicates(
        self,
        operation: PatchOperation,
        index: int,
        result: ValidationResult,
    ) -> None:
        """Validate that object IDs don't already exist."""
        # Check for explicit ID in payload
        object_id = operation.payload.get("id")
        if object_id and object_id in self.existing_ids:
            result.add_error(
                ValidationErrorType.DUPLICATE_OBJECT,
                f"Object with ID '{object_id}' already exists",
                operation_index=index,
                details={"object_id": object_id},
            )

    def _validate_operation_specific(
        self,
        op_type: OperationType,
        operation: PatchOperation,
        index: int,
        result: ValidationResult,
    ) -> None:
        """Perform operation-specific validation."""
        if op_type == OperationType.PROMOTE_FINDING_CANDIDATE:
            # Check that finding exists
            finding_id = operation.payload.get("finding_id")
            if finding_id and finding_id not in self.existing_ids:
                result.add_error(
                    ValidationErrorType.OBJECT_NOT_FOUND,
                    f"Finding candidate not found: {finding_id}",
                    operation_index=index,
                    details={"finding_id": finding_id},
                )

        elif op_type == OperationType.RECORD_EXECUTION_RESULT:
            # Validate plan_id exists
            plan_id = operation.payload.get("plan_id")
            if plan_id and plan_id not in self.existing_ids:
                result.add_warning(
                    f"Execution plan '{plan_id}' may not exist - verify manually"
                )

        elif op_type == OperationType.ADD_FINDING_CANDIDATE:
            # Validate severity
            severity = operation.payload.get("severity")
            valid_severities = {"critical", "high", "medium", "low", "info"}
            if severity and severity.lower() not in valid_severities:
                result.add_error(
                    ValidationErrorType.INVALID_PAYLOAD,
                    f"Invalid severity: {severity}",
                    operation_index=index,
                    field_name="severity",
                )

            # High/critical severity requires 2+ evidence
            evidence_ids = operation.payload.get("evidence_ids", [])
            if severity and severity.lower() in {"critical", "high"}:
                if len(evidence_ids) < 2:
                    result.add_error(
                        ValidationErrorType.MISSING_FIELD,
                        f"High/Critical severity findings require at least 2 evidence items",
                        operation_index=index,
                        field_name="evidence_ids",
                    )
