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
