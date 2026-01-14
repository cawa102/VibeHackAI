"""
Orchestrator module for PentestAgent.

Provides the control plane connecting human interface with agents,
handling approval, routing, and state management.
"""

from .router import Router, Phase, PhaseTransition
from .context_builder import ContextBuilder, ContextBundle
from .approval_gate import ApprovalGate, ApprovalRequest, ApprovalResult
from .stop_monitor import StopMonitor, StopCondition, StopReason
from .audit_logger import OrchestratorAuditLogger, AuditEvent
from .orchestrator import Orchestrator, OrchestratorConfig
from .workflow import (
    InteractiveWorkflow,
    WorkflowPhase,
    WorkflowState,
    ExecutionPlan,
    PlanStep,
    TaskType,
    TaskStatus,
    UserProposal,
    UserResponse,
    AgentTaskResult,
)

# New FR implementations
from .phase_approval import (
    PhaseApprovalGate,
    PhaseApprovalRequest,
    PhaseApprovalResponse,
    PhaseApprovalStatus,
    create_phase_approval_display,
)
from .escalation import (
    PolicyEscalationManager,
    EscalationRequest,
    EscalationResponse,
    EscalationType,
    EscalationSeverity,
    EscalationStatus,
    EscalationContext,
)
from .override import (
    OverrideManager,
    OverrideRequest,
    OverrideDecision,
    StopCategory,
    create_override_display,
    check_override_allowed,
)

__all__ = [
    # Router
    "Router",
    "Phase",
    "PhaseTransition",
    # Context
    "ContextBuilder",
    "ContextBundle",
    # Approval (legacy command-level)
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalResult",
    # Stop Monitor
    "StopMonitor",
    "StopCondition",
    "StopReason",
    # Audit
    "OrchestratorAuditLogger",
    "AuditEvent",
    # Main
    "Orchestrator",
    "OrchestratorConfig",
    # Interactive Workflow
    "InteractiveWorkflow",
    "WorkflowPhase",
    "WorkflowState",
    "ExecutionPlan",
    "PlanStep",
    "TaskType",
    "TaskStatus",
    "UserProposal",
    "UserResponse",
    "AgentTaskResult",
    # Phase Approval (FR-1)
    "PhaseApprovalGate",
    "PhaseApprovalRequest",
    "PhaseApprovalResponse",
    "PhaseApprovalStatus",
    "create_phase_approval_display",
    # Escalation (FR-3)
    "PolicyEscalationManager",
    "EscalationRequest",
    "EscalationResponse",
    "EscalationType",
    "EscalationSeverity",
    "EscalationStatus",
    "EscalationContext",
    # Override (FR-4)
    "OverrideManager",
    "OverrideRequest",
    "OverrideDecision",
    "StopCategory",
    "create_override_display",
    "check_override_allowed",
]
