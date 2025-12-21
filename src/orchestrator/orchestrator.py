"""
Main Orchestrator for PentestAgent.

Coordinates agents, manages workflow, and handles state updates.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

from .router import Router, Phase, PhaseTransition, TransitionReason, PHASE_AGENTS
from .context_builder import ContextBuilder, ContextBundle
from .approval_gate import ApprovalGate, ApprovalRequest, ApprovalResult
from .stop_monitor import StopMonitor, StopCondition, StopReason
from .audit_logger import OrchestratorAuditLogger, AuditEventType

if TYPE_CHECKING:
    from ..storage.state_store import StateStore
    from ..storage.evidence_ledger import EvidenceLedger
    from ..patch.patch import Patch
    from ..patch.applier import PatchApplier, ApplyResult
    from ..patch.validator import PatchValidator


@dataclass
class OrchestratorConfig:
    """Configuration for orchestrator."""
    session_id: str
    scope_tag: str
    approval_timeout_minutes: int = 5
    consecutive_error_threshold: int = 2
    total_error_threshold: int = 10
    auto_advance: bool = False  # Auto-advance phases without prompts
    require_all_approvals: bool = True


@dataclass
class AgentResult:
    """Result from an agent invocation."""
    agent_type: str
    success: bool
    patch: Optional["Patch"] = None
    phase_result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: Optional[int] = None


# Type for agent handler function
AgentHandler = Callable[[ContextBundle], AgentResult]


class Orchestrator:
    """
    Main orchestrator coordinating the penetration testing workflow.

    Responsibilities:
    - Route workflow between phases
    - Build context bundles for agents
    - Handle approval requests
    - Monitor for stop conditions
    - Apply agent patches to state
    - Maintain audit trail
    """

    def __init__(
        self,
        state_store: "StateStore",
        evidence_ledger: "EvidenceLedger",
        config: OrchestratorConfig,
        patch_applier: Optional["PatchApplier"] = None,
        approval_callback: Optional[Callable[[ApprovalRequest], ApprovalResult]] = None,
    ):
        """
        Initialize orchestrator.

        Args:
            state_store: State store for state management.
            evidence_ledger: Evidence ledger for evidence.
            config: Orchestrator configuration.
            patch_applier: Optional patch applier (created if not provided).
            approval_callback: Callback for approval requests.
        """
        self.state_store = state_store
        self.evidence_ledger = evidence_ledger
        self.config = config

        # Initialize components
        self.router = Router(state_store)
        self.context_builder = ContextBuilder(
            state_store, evidence_ledger,
            config.session_id, config.scope_tag
        )
        self.approval_gate = ApprovalGate(
            state_store,
            timeout_minutes=config.approval_timeout_minutes,
            approval_callback=approval_callback,
        )
        self.stop_monitor = StopMonitor(
            state_store,
            consecutive_error_threshold=config.consecutive_error_threshold,
            total_error_threshold=config.total_error_threshold,
        )
        self.audit_logger = OrchestratorAuditLogger(
            state_store, config.session_id
        )

        # Patch applier (create if not provided)
        if patch_applier:
            self.patch_applier = patch_applier
        else:
            from ..patch.applier import PatchApplier
            self.patch_applier = PatchApplier(
                state_store, evidence_ledger,
                validate_before_apply=True,
            )

        # Agent handlers
        self._agent_handlers: Dict[str, AgentHandler] = {}

        # State
        self._started = False
        self._stopped = False

    @property
    def current_phase(self) -> Phase:
        """Get current phase."""
        return self.router.current_phase

    @property
    def is_running(self) -> bool:
        """Check if orchestrator is running."""
        return self._started and not self._stopped

    def register_agent_handler(
        self,
        agent_type: str,
        handler: AgentHandler,
    ) -> None:
        """
        Register a handler for an agent type.

        Args:
            agent_type: Type of agent (recon_agent, etc.).
            handler: Function to invoke the agent.
        """
        self._agent_handlers[agent_type] = handler

    def start(self) -> None:
        """Start the orchestrator."""
        if self._started:
            raise RuntimeError("Orchestrator already started")

        self._started = True
        self._stopped = False

        self.audit_logger.log_session_start(
            self.config.scope_tag,
            details={"config": self.config.__dict__},
        )

        # Transition from INIT to RECON
        self.router.advance(reason=TransitionReason.NORMAL)
        self.audit_logger.log_phase_transition(
            Phase.INIT.value,
            Phase.RECON.value,
            "Session started",
        )

    def stop(self, reason: str, triggered_by: str = "user") -> None:
        """
        Stop the orchestrator.

        Args:
            reason: Reason for stopping.
            triggered_by: Who triggered the stop.
        """
        if not self._started:
            return

        self._stopped = True
        self.router.stop(reason, triggered_by)

        self.audit_logger.log_session_end(
            reason,
            details={"triggered_by": triggered_by},
        )

        # Save emergency snapshot if needed
        if self.stop_monitor.should_stop:
            self.stop_monitor.save_emergency_snapshot()

    def run_phase(
        self,
        instructions: Optional[str] = None,
    ) -> AgentResult:
        """
        Run the current phase agent.

        Args:
            instructions: Optional instructions for the agent.

        Returns:
            AgentResult from the agent.
        """
        if not self.is_running:
            raise RuntimeError("Orchestrator not running")

        if self.stop_monitor.should_stop:
            raise RuntimeError(
                f"Stop condition active: {self.stop_monitor.stop_reason}"
            )

        phase = self.current_phase
        agent_type = self.router.get_current_agent()

        if not agent_type:
            raise RuntimeError(f"No agent for phase: {phase}")

        handler = self._agent_handlers.get(agent_type)
        if not handler:
            raise RuntimeError(f"No handler registered for: {agent_type}")

        # Build context bundle
        previous_result = self.router.get_phase_result(
            self._get_previous_phase(phase)
        )
        context = self.context_builder.build(
            agent_type, phase, previous_result, instructions
        )

        # Log invocation
        self.audit_logger.log_agent_invoked(
            agent_type, phase.value,
            context_size=len(str(context.to_dict())),
        )

        start_time = datetime.utcnow()

        try:
            # Invoke agent
            result = handler(context)

            # Calculate duration
            duration_ms = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )
            result.duration_ms = duration_ms

            # Log completion
            self.audit_logger.log_agent_completed(
                agent_type, phase.value, result.success, duration_ms
            )

            # Process result
            if result.success:
                self.stop_monitor.record_success()
                if result.patch:
                    self._process_patch(result.patch)
            else:
                self._handle_agent_failure(result)

            return result

        except Exception as e:
            duration_ms = int(
                (datetime.utcnow() - start_time).total_seconds() * 1000
            )

            self.audit_logger.log_agent_failed(
                agent_type, phase.value, str(e)
            )

            return AgentResult(
                agent_type=agent_type,
                success=False,
                error=str(e),
                duration_ms=duration_ms,
            )

    def _get_previous_phase(self, current: Phase) -> Optional[Phase]:
        """Get the phase before current."""
        from .router import PHASE_ORDER
        try:
            idx = PHASE_ORDER.index(current)
            if idx > 0:
                return PHASE_ORDER[idx - 1]
        except ValueError:
            pass
        return None

    def _process_patch(self, patch: "Patch") -> "ApplyResult":
        """Process a patch from an agent."""
        self.audit_logger.log_patch_received(
            patch.patch_id,
            patch.agent_id,
            patch.operation_count(),
        )

        # Check for approval requirements
        if patch.requires_approval():
            if not self._handle_approval(patch):
                from ..patch.applier import ApplyResult
                self.audit_logger.log_patch_rejected(
                    patch.patch_id,
                    "Approval denied",
                )
                return ApplyResult(
                    success=False,
                    patch_id=patch.patch_id,
                    error="Approval denied",
                )

        # Apply patch
        result = self.patch_applier.apply(patch)

        if result.success:
            self.audit_logger.log_patch_applied(
                patch.patch_id,
                result.operations_applied,
                result.new_state_version or 0,
            )
        else:
            self.audit_logger.log_patch_rejected(
                patch.patch_id,
                result.error or "Unknown error",
                result.validation_errors,
            )

        return result

    def _handle_approval(self, patch: "Patch") -> bool:
        """Handle approval for a patch."""
        # Find operations requiring approval
        for op in patch.operations:
            if op.requires_approval:
                request = self.approval_gate.create_request(
                    operation=op.op if isinstance(op.op, str) else op.op.value,
                    target=op.target,
                    description=f"Operation from {patch.agent_id}",
                    patch_id=patch.patch_id,
                    details=op.payload,
                )

                self.audit_logger.log_approval_requested(
                    request.request_id,
                    request.operation,
                    request.target,
                )

                result = self.approval_gate.request_approval(request)

                if result.approved:
                    self.audit_logger.log_approval_granted(
                        request.request_id,
                        result.responded_by or "unknown",
                    )
                else:
                    self.audit_logger.log_approval_denied(
                        request.request_id,
                        result.responded_by or "system",
                        result.reason or "No reason provided",
                    )
                    return False

        return True

    def _handle_agent_failure(self, result: AgentResult) -> None:
        """Handle agent failure."""
        error_class = "agent_error"
        if result.error:
            # Try to classify error
            error_lower = result.error.lower()
            if "network" in error_lower or "connection" in error_lower:
                error_class = "network"
            elif "timeout" in error_lower:
                error_class = "timeout"
            elif "permission" in error_lower or "denied" in error_lower:
                error_class = "permission"

        condition = self.stop_monitor.record_error(
            error_class, result.error
        )

        if condition:
            self.audit_logger.log_stop_condition(
                condition.reason.value,
                condition.severity,
                condition.details,
            )

    def advance_phase(
        self,
        phase_result: Optional[Dict[str, Any]] = None,
    ) -> Optional[PhaseTransition]:
        """
        Advance to the next phase.

        Args:
            phase_result: Result from current phase.

        Returns:
            PhaseTransition if successful, None if cannot advance.
        """
        if not self.is_running:
            return None

        # Check if we can advance
        if not self.router.can_advance(phase_result):
            return None

        # Check for rollback
        if phase_result:
            rollback_phase = self.router.should_rollback(phase_result)
            if rollback_phase:
                transition = self.router.rollback_to(
                    rollback_phase,
                    details=phase_result.get("rollback_reason"),
                )
                self.audit_logger.log_phase_transition(
                    transition.from_phase.value,
                    transition.to_phase.value,
                    f"Rollback: {transition.details}",
                )
                return transition

            # Check for skip
            if self.router.should_skip(phase_result):
                next_phase = self.router.get_next_phase()
                if next_phase:
                    # Skip one phase
                    after_next = None
                    from .router import PHASE_ORDER
                    try:
                        idx = PHASE_ORDER.index(next_phase)
                        if idx < len(PHASE_ORDER) - 1:
                            after_next = PHASE_ORDER[idx + 1]
                    except ValueError:
                        pass

                    if after_next:
                        transition = self.router.skip_to(
                            after_next,
                            details="Sufficient information from previous phases",
                        )
                        self.audit_logger.log_phase_transition(
                            transition.from_phase.value,
                            transition.to_phase.value,
                            f"Skip: {transition.details}",
                        )
                        return transition

        # Normal advance
        transition = self.router.advance(phase_result)
        self.audit_logger.log_phase_transition(
            transition.from_phase.value,
            transition.to_phase.value,
            "Normal progression",
        )
        return transition

    def run_workflow(self) -> Dict[str, Any]:
        """
        Run the complete workflow from start to finish.

        Returns:
            Summary of workflow execution.
        """
        if not self._started:
            self.start()

        results = []
        transitions = []

        while self.is_running:
            phase = self.current_phase

            # Check for completion or stop
            if phase in (Phase.COMPLETED, Phase.STOPPED):
                break

            # Check stop conditions
            if self.stop_monitor.should_stop:
                self.stop(
                    f"Stop condition: {self.stop_monitor.stop_reason}",
                    "stop_monitor",
                )
                break

            # Run current phase
            try:
                result = self.run_phase()
                results.append({
                    "phase": phase.value,
                    "agent": result.agent_type,
                    "success": result.success,
                    "error": result.error,
                    "duration_ms": result.duration_ms,
                })

                # Advance phase
                phase_result = result.phase_result or {
                    "success": result.success,
                    "has_blocking_error": not result.success,
                }

                transition = self.advance_phase(phase_result)
                if transition:
                    transitions.append(transition.to_dict())

            except RuntimeError as e:
                self.audit_logger.log_error(str(e))
                break

        return {
            "final_phase": self.current_phase.value,
            "total_phases_run": len(results),
            "results": results,
            "transitions": transitions,
            "stopped": self._stopped,
            "stop_reason": self.stop_monitor.stop_reason.value if self.stop_monitor.stop_reason else None,
        }

    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status."""
        return {
            "session_id": self.config.session_id,
            "scope_tag": self.config.scope_tag,
            "current_phase": self.current_phase.value,
            "is_running": self.is_running,
            "state_version": self.state_store.get_version(),
            "router_state": self.router.get_state(),
            "stop_monitor_status": self.stop_monitor.get_status(),
            "pending_approvals": len(self.approval_gate.get_pending_requests()),
            "audit_events_count": self.audit_logger.count_events(),
        }

    # ========================================
    # Interactive Workflow Methods
    # ========================================

    def create_interactive_workflow(
        self,
        planner_handler: Callable,
        user_callback: Callable,
    ) -> "InteractiveWorkflow":
        """
        Create an interactive workflow instance.

        Args:
            planner_handler: Handler for planner agent.
            user_callback: Callback for user interaction.

        Returns:
            InteractiveWorkflow instance.
        """
        from .workflow import InteractiveWorkflow

        def planner_callback(target: str, context: Dict[str, Any]):
            """Invoke planner to create initial plan."""
            return self._invoke_planner_for_plan(planner_handler, target, context)

        def plan_update_callback(plan, result):
            """Invoke planner to update plan based on results."""
            return self._invoke_planner_for_update(planner_handler, plan, result)

        def agent_execution_callback(step, context):
            """Execute agent for a plan step."""
            return self._execute_plan_step(step, context)

        workflow = InteractiveWorkflow(
            session_id=self.config.session_id,
            state_store=self.state_store,
            evidence_ledger=self.evidence_ledger,
            planner_callback=planner_callback,
            plan_update_callback=plan_update_callback,
            user_interaction_callback=user_callback,
            agent_execution_callback=agent_execution_callback,
        )

        return workflow

    def _invoke_planner_for_plan(
        self,
        planner_handler: Callable,
        target: str,
        context: Dict[str, Any],
    ) -> "ExecutionPlan":
        """
        Invoke planner to create initial execution plan.

        Args:
            planner_handler: Planner agent handler.
            target: Target IP/host.
            context: Current context.

        Returns:
            ExecutionPlan created by planner.
        """
        from .workflow import ExecutionPlan, PlanStep, TaskType, TaskStatus
        import uuid

        # Build context bundle for planner
        planner_context = self.context_builder.build(
            "planner_agent",
            Phase.PLANNER,
            context,
            f"Create penetration test plan for target: {target}",
        )

        # Invoke planner
        self.audit_logger.log_agent_invoked(
            "planner_agent",
            "planning",
            context_size=len(str(context)),
        )

        result = planner_handler(planner_context)

        self.audit_logger.log_agent_completed(
            "planner_agent",
            "planning",
            result.success,
            result.duration_ms or 0,
        )

        # Convert planner result to ExecutionPlan
        now = datetime.utcnow().isoformat() + "Z"
        steps = []

        # Default reconnaissance step
        steps.append(PlanStep(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            order=1,
            task_type=TaskType.RECONNAISSANCE,
            description="Initial reconnaissance: port scan and service detection",
            target=target,
            agent="recon_agent",
            parameters={"scan_type": "service_scan", "ports": "1-1000"},
            requires_approval=False,
        ))

        # Default enumeration step
        steps.append(PlanStep(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            order=2,
            task_type=TaskType.ENUMERATION,
            description="Enumerate discovered services and gather details",
            target=target,
            agent="enumeration_agent",
            parameters={},
            requires_approval=False,
        ))

        # Vulnerability scan step
        steps.append(PlanStep(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            order=3,
            task_type=TaskType.VULNERABILITY_SCAN,
            description="Scan for known vulnerabilities in discovered services",
            target=target,
            agent="planner_agent",
            parameters={"mode": "vulnerability_assessment"},
            requires_approval=False,
        ))

        # Add exploitation steps based on planner output
        if result.phase_result and result.phase_result.get("vuln_candidates_found", 0) > 0:
            steps.append(PlanStep(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                order=4,
                task_type=TaskType.EXPLOITATION,
                description="Attempt exploitation of identified vulnerabilities",
                target=target,
                agent="exploitation_agent",
                parameters={},
                requires_approval=True,  # Always require approval for exploitation
            ))

        return ExecutionPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            version=1,
            target=target,
            steps=steps,
            created_at=now,
            updated_at=now,
            rationale="Initial penetration test plan based on target analysis",
            risk_assessment="medium",
            estimated_success_rate=0.6,
        )

    def _invoke_planner_for_update(
        self,
        planner_handler: Callable,
        current_plan: "ExecutionPlan",
        last_result: "AgentTaskResult",
    ) -> "ExecutionPlan":
        """
        Invoke planner to update plan based on execution results.

        Args:
            planner_handler: Planner agent handler.
            current_plan: Current execution plan.
            last_result: Result from last executed step.

        Returns:
            Updated ExecutionPlan.
        """
        from .workflow import PlanStep, TaskType
        import uuid

        # Check if we need to update the plan based on results
        needs_update = False
        new_steps = []

        # Analyze last result
        if last_result.success:
            result_data = last_result.result_data

            # If recon found new services, add enumeration steps
            if last_result.agent == "recon_agent":
                services = result_data.get("services_found", 0)
                if services > 0:
                    needs_update = True

            # If enumeration found vulnerabilities, add exploitation steps
            elif last_result.agent == "enumeration_agent":
                vulns = result_data.get("vulnerabilities_found", 0)
                if vulns > 0:
                    needs_update = True
                    # Add verification step
                    new_steps.append(PlanStep(
                        step_id=f"step-{uuid.uuid4().hex[:8]}",
                        order=len(current_plan.steps) + 1,
                        task_type=TaskType.VERIFICATION,
                        description="Verify exploitability of discovered vulnerabilities",
                        target=current_plan.target,
                        agent="planner_agent",
                        parameters={"mode": "verify"},
                        requires_approval=False,
                    ))

            # If vulnerability scan found high/critical issues
            elif last_result.agent == "planner_agent":
                high_vulns = result_data.get("high_severity_vulns", 0)
                if high_vulns > 0 and not any(
                    s.task_type == TaskType.EXPLOITATION
                    for s in current_plan.steps
                ):
                    needs_update = True
                    new_steps.append(PlanStep(
                        step_id=f"step-{uuid.uuid4().hex[:8]}",
                        order=len(current_plan.steps) + 1,
                        task_type=TaskType.EXPLOITATION,
                        description=f"Exploit {high_vulns} high/critical vulnerabilities",
                        target=current_plan.target,
                        agent="exploitation_agent",
                        parameters={"vuln_count": high_vulns},
                        requires_approval=True,
                    ))

        # Update plan if needed
        if needs_update and new_steps:
            current_plan.steps.extend(new_steps)
            current_plan.version += 1
            current_plan.updated_at = datetime.utcnow().isoformat() + "Z"
            current_plan.rationale = f"Plan updated based on {last_result.agent} results"

        return current_plan

    def _execute_plan_step(
        self,
        step: "PlanStep",
        context: Dict[str, Any],
    ) -> "AgentTaskResult":
        """
        Execute a plan step using the appropriate agent.

        Args:
            step: Plan step to execute.
            context: Execution context.

        Returns:
            AgentTaskResult from agent execution.
        """
        from .workflow import AgentTaskResult

        agent_type = step.agent
        handler = self._agent_handlers.get(agent_type)

        if not handler:
            return AgentTaskResult(
                task_id=step.step_id,
                agent=agent_type,
                success=False,
                result_data={},
                evidence_ids=[],
                observations=[],
                error=f"No handler registered for agent: {agent_type}",
            )

        # Map task type to phase
        phase_map = {
            "recon_agent": Phase.RECON,
            "enumeration_agent": Phase.ENUMERATION,
            "planner_agent": Phase.PLANNER,
            "exploitation_agent": Phase.EXPLOITATION,
        }
        phase = phase_map.get(agent_type, Phase.RECON)

        # Build context bundle
        agent_context = self.context_builder.build(
            agent_type,
            phase,
            context,
            step.description,
        )

        # Log invocation
        self.audit_logger.log_agent_invoked(
            agent_type,
            phase.value,
            context_size=len(str(context)),
        )

        start_time = datetime.utcnow()

        try:
            result = handler(agent_context)
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            self.audit_logger.log_agent_completed(
                agent_type,
                phase.value,
                result.success,
                duration_ms,
            )

            # Extract evidence IDs from patch if available
            evidence_ids = []
            observations = []
            if result.patch:
                for op in result.patch.operations:
                    if op.op.value == "add_evidence":
                        evidence_ids.append(op.payload.get("evidence_id", ""))
                    elif op.op.value == "add_observation":
                        observations.append(op.payload)

            return AgentTaskResult(
                task_id=step.step_id,
                agent=agent_type,
                success=result.success,
                result_data=result.phase_result or {},
                evidence_ids=evidence_ids,
                observations=observations,
                error=result.error,
                duration_ms=duration_ms,
            )

        except Exception as e:
            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

            self.audit_logger.log_agent_failed(agent_type, phase.value, str(e))

            return AgentTaskResult(
                task_id=step.step_id,
                agent=agent_type,
                success=False,
                result_data={},
                evidence_ids=[],
                observations=[],
                error=str(e),
                duration_ms=duration_ms,
            )


# Type alias for workflow imports
from .workflow import (
    InteractiveWorkflow,
    ExecutionPlan,
    PlanStep,
    TaskType,
    TaskStatus,
    WorkflowPhase,
    UserProposal,
    UserResponse,
    AgentTaskResult,
)
