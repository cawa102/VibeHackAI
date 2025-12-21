"""
Orchestrator module for PentestAgent.

Provides the control plane connecting human interface with agents,
handling approval, routing, and state management.
"""

from .approval_gate import ApprovalGate, ApprovalRequest, ApprovalResult
from .audit_logger import AuditEvent, OrchestratorAuditLogger
from .context_builder import ContextBuilder, ContextBundle
from .orchestrator import Orchestrator, OrchestratorConfig
from .router import Phase, PhaseTransition, Router
from .stop_monitor import StopCondition, StopMonitor, StopReason
from .workflow import (
    AgentTaskResult,
    ExecutionPlan,
    InteractiveWorkflow,
    PlanStep,
    TaskStatus,
    TaskType,
    UserProposal,
    UserResponse,
    WorkflowPhase,
    WorkflowState,
)

__all__ = [
    # Router
    "Router",
    "Phase",
    "PhaseTransition",
    # Context
    "ContextBuilder",
    "ContextBundle",
    # Approval
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
]
