"""
Base Agent class for PentestAgent.

Provides common functionality for all agents.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..orchestrator.context_builder import ContextBundle
    from ..patch.patch import Patch, PatchOperation


class AgentType(str, Enum):
    """Types of agents in the system."""
    RECON = "recon_agent"
    ENUMERATION = "enumeration_agent"
    PLANNER = "planner_agent"
    EXPLOITATION = "exploitation_agent"
    REPORTING = "reporting_agent"


class AgentStatus(str, Enum):
    """Status of agent execution."""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass
class AgentConfig:
    """Configuration for an agent."""
    agent_type: AgentType
    timeout_seconds: int = 600  # 10 minutes default
    max_retries: int = 2
    retry_delay_seconds: int = 5
    skip_on_sufficient_data: bool = True
    verbose: bool = False


@dataclass
class AgentContext:
    """
    Context provided to an agent for execution.

    Wraps the ContextBundle with additional runtime info.
    """
    bundle: "ContextBundle"
    config: AgentConfig
    run_id: str = dataclass_field(default_factory=lambda: f"run-{uuid.uuid4().hex[:8]}")
    started_at: Optional[datetime] = None

    @property
    def session_id(self) -> str:
        """Get session ID from bundle."""
        return self.bundle.session_id

    @property
    def scope_tag(self) -> str:
        """Get scope tag from bundle."""
        return self.bundle.scope_tag

    @property
    def state_version(self) -> int:
        """Get state version from bundle."""
        return self.bundle.state_version

    @property
    def scope(self) -> Optional[Dict[str, Any]]:
        """Get scope from bundle."""
        return self.bundle.scope

    @property
    def target_profile(self) -> Optional[Dict[str, Any]]:
        """Get target profile from bundle."""
        return self.bundle.target_profile

    @property
    def observations(self) -> List[Dict[str, Any]]:
        """Get observations from bundle."""
        return self.bundle.observations

    @property
    def instructions(self) -> Optional[str]:
        """Get instructions from bundle."""
        return self.bundle.instructions


@dataclass
class AgentOutput:
    """
    Output from an agent execution.

    Contains the patch to apply and execution metadata.
    """
    agent_type: str
    run_id: str
    success: bool
    patch: Optional["Patch"] = None
    phase_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    warnings: List[str] = dataclass_field(default_factory=list)
    decision_traces: List[Dict[str, Any]] = dataclass_field(default_factory=list)
    duration_ms: Optional[int] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_type": self.agent_type,
            "run_id": self.run_id,
            "success": self.success,
            "patch_id": self.patch.patch_id if self.patch else None,
            "phase_result": self.phase_result,
            "error": self.error,
            "warnings": self.warnings,
            "decision_traces": self.decision_traces,
            "duration_ms": self.duration_ms,
            "started_at": self.started_at.isoformat() + "Z" if self.started_at else None,
            "completed_at": self.completed_at.isoformat() + "Z" if self.completed_at else None,
        }


@dataclass
class DecisionTrace:
    """Record of a decision made by an agent."""
    decision_id: str
    decision_type: str
    description: str
    reasoning: str
    timestamp: datetime = dataclass_field(default_factory=datetime.utcnow)
    inputs: Optional[Dict[str, Any]] = None
    outputs: Optional[Dict[str, Any]] = None
    alternatives_considered: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "decision_id": self.decision_id,
            "decision_type": self.decision_type,
            "description": self.description,
            "reasoning": self.reasoning,
            "timestamp": self.timestamp.isoformat() + "Z",
            "inputs": self.inputs,
            "outputs": self.outputs,
            "alternatives_considered": self.alternatives_considered,
        }


class BaseAgent(ABC):
    """
    Abstract base class for all agents.

    Provides common functionality for:
    - Context handling
    - Patch generation
    - Error handling
    - Decision tracing
    """

    def __init__(self, config: AgentConfig):
        """
        Initialize agent.

        Args:
            config: Agent configuration.
        """
        self.config = config
        self._status = AgentStatus.IDLE
        self._context: Optional[AgentContext] = None
        self._decisions: List[DecisionTrace] = []
        self._warnings: List[str] = []

    @property
    def agent_type(self) -> AgentType:
        """Get agent type."""
        return self.config.agent_type

    @property
    def status(self) -> AgentStatus:
        """Get current status."""
        return self._status

    def run(self, context: AgentContext) -> AgentOutput:
        """
        Execute the agent.

        Args:
            context: Agent context with bundle and config.

        Returns:
            AgentOutput with results.
        """
        self._status = AgentStatus.RUNNING
        self._context = context
        self._decisions = []
        self._warnings = []
        context.started_at = datetime.utcnow()

        try:
            # Validate context
            validation_error = self._validate_context(context)
            if validation_error:
                return self._create_error_output(
                    context, validation_error
                )

            # Check for skip condition
            if self.config.skip_on_sufficient_data:
                skip_reason = self._should_skip(context)
                if skip_reason:
                    self._record_decision(
                        "skip",
                        f"Skipping {self.agent_type.value}",
                        skip_reason,
                    )
                    return self._create_skip_output(context, skip_reason)

            # Execute main logic
            output = self._execute(context)

            self._status = AgentStatus.COMPLETED if output.success else AgentStatus.FAILED
            return output

        except Exception as e:
            self._status = AgentStatus.FAILED
            return self._create_error_output(context, str(e))

        finally:
            self._context = None

    @abstractmethod
    def _execute(self, context: AgentContext) -> AgentOutput:
        """
        Execute agent-specific logic.

        Args:
            context: Agent context.

        Returns:
            AgentOutput with results.
        """
        pass

    def _validate_context(self, context: AgentContext) -> Optional[str]:
        """
        Validate the context before execution.

        Args:
            context: Agent context.

        Returns:
            Error message if invalid, None if valid.
        """
        if not context.bundle:
            return "No context bundle provided"

        if not context.scope:
            return "No scope defined in context"

        return None

    def _should_skip(self, context: AgentContext) -> Optional[str]:
        """
        Check if agent should skip execution.

        Override in subclasses for specific skip logic.

        Args:
            context: Agent context.

        Returns:
            Skip reason if should skip, None otherwise.
        """
        return None

    def _record_decision(
        self,
        decision_type: str,
        description: str,
        reasoning: str,
        inputs: Optional[Dict[str, Any]] = None,
        outputs: Optional[Dict[str, Any]] = None,
        alternatives: Optional[List[str]] = None,
    ) -> DecisionTrace:
        """
        Record a decision made during execution.

        Args:
            decision_type: Type of decision.
            description: Short description.
            reasoning: Reasoning behind decision.
            inputs: Input data for decision.
            outputs: Output data from decision.
            alternatives: Alternatives considered.

        Returns:
            The created DecisionTrace.
        """
        trace = DecisionTrace(
            decision_id=f"dec-{uuid.uuid4().hex[:8]}",
            decision_type=decision_type,
            description=description,
            reasoning=reasoning,
            inputs=inputs,
            outputs=outputs,
            alternatives_considered=alternatives,
        )
        self._decisions.append(trace)
        return trace

    def _add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self._warnings.append(warning)

    def _create_patch(
        self,
        context: AgentContext,
        operations: List["PatchOperation"],
    ) -> "Patch":
        """
        Create a patch with the given operations.

        Args:
            context: Agent context.
            operations: List of patch operations.

        Returns:
            The created Patch.
        """
        from ..patch.patch import Patch

        return Patch(
            patch_id=f"patch-{uuid.uuid4().hex[:8]}",
            session_id=context.session_id,
            agent_id=self.agent_type.value,
            base_state_version=context.state_version,
            operations=operations,
            scope_tag=context.scope_tag,
        )

    def _create_success_output(
        self,
        context: AgentContext,
        patch: "Patch",
        phase_result: Optional[Dict[str, Any]] = None,
    ) -> AgentOutput:
        """
        Create successful output.

        Args:
            context: Agent context.
            patch: The patch to apply.
            phase_result: Phase result data.

        Returns:
            AgentOutput indicating success.
        """
        completed_at = datetime.utcnow()
        duration_ms = None
        if context.started_at:
            duration_ms = int(
                (completed_at - context.started_at).total_seconds() * 1000
            )

        return AgentOutput(
            agent_type=self.agent_type.value,
            run_id=context.run_id,
            success=True,
            patch=patch,
            phase_result=phase_result,
            warnings=self._warnings.copy(),
            decision_traces=[d.to_dict() for d in self._decisions],
            duration_ms=duration_ms,
            started_at=context.started_at,
            completed_at=completed_at,
        )

    def _create_error_output(
        self,
        context: AgentContext,
        error: str,
    ) -> AgentOutput:
        """
        Create error output.

        Args:
            context: Agent context.
            error: Error message.

        Returns:
            AgentOutput indicating failure.
        """
        completed_at = datetime.utcnow()
        duration_ms = None
        if context.started_at:
            duration_ms = int(
                (completed_at - context.started_at).total_seconds() * 1000
            )

        return AgentOutput(
            agent_type=self.agent_type.value,
            run_id=context.run_id,
            success=False,
            error=error,
            warnings=self._warnings.copy(),
            decision_traces=[d.to_dict() for d in self._decisions],
            duration_ms=duration_ms,
            started_at=context.started_at,
            completed_at=completed_at,
        )

    def _create_skip_output(
        self,
        context: AgentContext,
        reason: str,
    ) -> AgentOutput:
        """
        Create skip output.

        Args:
            context: Agent context.
            reason: Skip reason.

        Returns:
            AgentOutput indicating skip.
        """
        completed_at = datetime.utcnow()
        duration_ms = None
        if context.started_at:
            duration_ms = int(
                (completed_at - context.started_at).total_seconds() * 1000
            )

        return AgentOutput(
            agent_type=self.agent_type.value,
            run_id=context.run_id,
            success=True,
            phase_result={
                "skipped": True,
                "skip_reason": reason,
            },
            warnings=self._warnings.copy(),
            decision_traces=[d.to_dict() for d in self._decisions],
            duration_ms=duration_ms,
            started_at=context.started_at,
            completed_at=completed_at,
        )

    def stop(self) -> None:
        """Stop agent execution."""
        self._status = AgentStatus.STOPPED
