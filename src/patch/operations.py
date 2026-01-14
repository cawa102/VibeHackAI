"""
Patch Operation Types for PentestAgent.

Defines the types of operations that can be performed through patches.
"""

from __future__ import annotations

from enum import Enum


class OperationType(str, Enum):
    """Types of patch operations."""

    # Evidence operations
    ADD_EVIDENCE = "add_evidence"

    # Observation operations
    ADD_OBSERVATION = "add_observation"

    # Target profile operations
    UPDATE_TARGET_PROFILE = "update_target_profile"

    # Vulnerability operations
    ADD_VULN_CANDIDATE = "add_vuln_candidate"

    # Exploit operations
    ADD_EXPLOIT_CANDIDATE = "add_exploit_candidate"

    # Execution plan operations
    PROPOSE_EXECUTION_PLAN = "propose_execution_plan"

    # Execution result operations
    RECORD_EXECUTION_RESULT = "record_execution_result"

    # Finding operations
    ADD_FINDING_CANDIDATE = "add_finding_candidate"
    PROMOTE_FINDING_CANDIDATE = "promote_finding_candidate"

    # Decision trace operations
    ADD_DECISION_TRACE = "add_decision_trace"


# Operations that require human approval
APPROVAL_REQUIRED_OPERATIONS = {
    OperationType.PROPOSE_EXECUTION_PLAN,
    OperationType.PROMOTE_FINDING_CANDIDATE,
}

# Operations that modify existing data (vs. adding new)
MODIFYING_OPERATIONS = {
    OperationType.UPDATE_TARGET_PROFILE,
    OperationType.PROMOTE_FINDING_CANDIDATE,
}

# Required fields for each operation payload
OPERATION_REQUIRED_FIELDS = {
    OperationType.ADD_EVIDENCE: ["data", "source_tool"],
    OperationType.ADD_OBSERVATION: ["tool", "action"],
    OperationType.UPDATE_TARGET_PROFILE: [],  # No required fields, partial updates allowed
    OperationType.ADD_VULN_CANDIDATE: ["title", "description", "affected_component", "source"],
    OperationType.ADD_EXPLOIT_CANDIDATE: ["title", "source"],
    OperationType.PROPOSE_EXECUTION_PLAN: ["title", "description", "target"],
    OperationType.RECORD_EXECUTION_RESULT: ["plan_id", "step_index"],
    OperationType.ADD_FINDING_CANDIDATE: [
        "title", "severity", "description", "impact",
        "affected_component", "remediation", "evidence_ids"
    ],
    OperationType.PROMOTE_FINDING_CANDIDATE: ["finding_id", "promoted_by"],
    OperationType.ADD_DECISION_TRACE: ["decision_type", "context", "rationale"],
}

# Target schema for each operation
OPERATION_TARGET_SCHEMAS = {
    OperationType.ADD_EVIDENCE: "EvidenceItem",
    OperationType.ADD_OBSERVATION: "Observation",
    OperationType.UPDATE_TARGET_PROFILE: "TargetProfile",
    OperationType.ADD_VULN_CANDIDATE: "VulnCandidate",
    OperationType.ADD_EXPLOIT_CANDIDATE: "ExploitCandidate",
    OperationType.PROPOSE_EXECUTION_PLAN: "ExecutionPlan",
    OperationType.RECORD_EXECUTION_RESULT: "ExecutionResult",
    OperationType.ADD_FINDING_CANDIDATE: "FindingCandidate",
    OperationType.PROMOTE_FINDING_CANDIDATE: "FindingCandidate",
    OperationType.ADD_DECISION_TRACE: "DecisionTrace",
}
