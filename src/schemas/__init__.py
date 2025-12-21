"""
Schemas module for VibeHackAI.

Provides Pydantic models for all data structures used in the system.
"""

from .base import BaseSchema, SchemaVersion
from .decision_trace import DecisionOption, DecisionTrace
from .evidence import EvidenceItem
from .execution_plan import ExecutionPlan, ExecutionStep
from .execution_result import ErrorClass, ExecutionResult, ExecutionStatus
from .exploit_candidate import ExploitCandidate, ExploitSource
from .finding_candidate import FindingCandidate, FindingSeverity
from .observation import Observation
from .scope import AllowedOperation, Scope, TargetSpec
from .target_profile import (
    HostInfo,
    PortInfo,
    ServiceInfo,
    TargetProfile,
    TechnologyStack,
)
from .validators import (
    validate_evidence_ids,
    validate_finding_evidence_requirement,
    validate_scope_tag,
)
from .vuln_candidate import ConfidenceLevel, Severity, VulnCandidate

__all__ = [
    # Base
    "BaseSchema",
    "SchemaVersion",
    # Scope
    "Scope",
    "TargetSpec",
    "AllowedOperation",
    # Target Profile
    "TargetProfile",
    "HostInfo",
    "PortInfo",
    "ServiceInfo",
    "TechnologyStack",
    # Evidence
    "EvidenceItem",
    # Observation
    "Observation",
    # Vulnerabilities
    "VulnCandidate",
    "Severity",
    "ConfidenceLevel",
    # Exploits
    "ExploitCandidate",
    "ExploitSource",
    # Execution
    "ExecutionPlan",
    "ExecutionStep",
    "ExecutionResult",
    "ExecutionStatus",
    "ErrorClass",
    # Findings
    "FindingCandidate",
    "FindingSeverity",
    # Decision
    "DecisionTrace",
    "DecisionOption",
    # Validators
    "validate_evidence_ids",
    "validate_scope_tag",
    "validate_finding_evidence_requirement",
]
