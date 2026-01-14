"""
Schemas module for PentestAgent.

Provides Pydantic models for all data structures used in the system.
"""

from .base import BaseSchema, SchemaVersion
from .scope import (
    Scope,
    TargetSpec,
    TargetType,
    AllowedOperation,
    ProofOfAccessPolicy,
    ProofOfAccessTracker,
)
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

# New schemas for FR implementation
from .cvss import (
    CVSS,
    CVSSVersion,
    CVSSSeverity,
    CVSSWithStatus,
    CVSSAssessmentStatus,
)
from .phase_brief import (
    PhaseBrief,
    PhasePlan,
    PhaseResult,
    PhaseType,
    RiskLevel,
    PlannedAction,
    SafetyConstraint,
)
from .approval_log import (
    ApprovalLog,
    ApprovalDecision,
    ApprovalType,
    OverrideLog,
    OverrideCategory,
    OverrideStatus,
    StopReport,
    can_override_stop,
    NON_OVERRIDABLE_CATEGORIES,
)
from .test_plan import (
    TestPlan,
    PhaseObjective,
    PhaseStatus,
    PlanChangeEntry,
    PlanChangeType,
    OpenQuestion,
    TestPlanRisk,
    create_initial_test_plan,
)

__all__ = [
    # Base
    "BaseSchema",
    "SchemaVersion",
    # Scope
    "Scope",
    "TargetSpec",
    "TargetType",
    "AllowedOperation",
    "ProofOfAccessPolicy",
    "ProofOfAccessTracker",
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
    # CVSS (FR-7)
    "CVSS",
    "CVSSVersion",
    "CVSSSeverity",
    "CVSSWithStatus",
    "CVSSAssessmentStatus",
    # Phase Brief (FR-1, FR-2)
    "PhaseBrief",
    "PhasePlan",
    "PhaseResult",
    "PhaseType",
    "RiskLevel",
    "PlannedAction",
    "SafetyConstraint",
    # Approval/Override Logs (FR-3, FR-4)
    "ApprovalLog",
    "ApprovalDecision",
    "ApprovalType",
    "OverrideLog",
    "OverrideCategory",
    "OverrideStatus",
    "StopReport",
    "can_override_stop",
    "NON_OVERRIDABLE_CATEGORIES",
    # Test Plan (FR-6)
    "TestPlan",
    "PhaseObjective",
    "PhaseStatus",
    "PlanChangeEntry",
    "PlanChangeType",
    "OpenQuestion",
    "TestPlanRisk",
    "create_initial_test_plan",
]
