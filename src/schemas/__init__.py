"""
Schemas module for PentestAgent.

Provides Pydantic models for all data structures used in the system.
"""

from .base import BaseSchema, SchemaVersion
from .scope import Scope, TargetSpec, AllowedOperation
from .target_profile import (
    TargetProfile,
    HostInfo,
    PortInfo,
    ServiceInfo,
    TechnologyStack,
)
from .evidence import EvidenceItem
from .observation import Observation
from .vuln_candidate import VulnCandidate, Severity, ConfidenceLevel
from .exploit_candidate import ExploitCandidate, ExploitSource
from .execution_plan import ExecutionPlan, ExecutionStep
from .execution_result import ExecutionResult, ExecutionStatus, ErrorClass
from .finding_candidate import FindingCandidate, FindingSeverity
from .decision_trace import DecisionTrace, DecisionOption
from .validators import (
    validate_evidence_ids,
    validate_scope_tag,
    validate_finding_evidence_requirement,
)

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
