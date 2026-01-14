"""
Patch Protocol module for PentestAgent.

Provides state update proposal mechanism with optimistic locking
and validation for safe state modifications.
"""

from .patch import Patch, PatchOperation
from .operations import OperationType
from .validator import (
    PatchValidator,
    ValidationError,
    ValidationResult,
)
from .applier import PatchApplier, ApplyResult
from .audit_log import PatchAuditLog, AuditEntry

__all__ = [
    # Core structures
    "Patch",
    "PatchOperation",
    "OperationType",
    # Validator
    "PatchValidator",
    "ValidationError",
    "ValidationResult",
    # Applier
    "PatchApplier",
    "ApplyResult",
    # Audit
    "PatchAuditLog",
    "AuditEntry",
]
