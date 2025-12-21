"""
Patch Protocol module for PentestAgent.

Provides state update proposal mechanism with optimistic locking
and validation for safe state modifications.
"""

from .applier import ApplyResult, PatchApplier
from .audit_log import AuditEntry, PatchAuditLog
from .operations import OperationType
from .patch import Patch, PatchOperation
from .validator import PatchValidator, ValidationError, ValidationResult

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
