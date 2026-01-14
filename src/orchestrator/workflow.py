"""
Interactive Workflow for PentestAgent.

Implements the step-by-step workflow:
1. User provides IP
2. Planner creates initial plan
3. Orchestrator proposes plan to user
4. User approves/modifies action
5. Orchestrator assigns task to agent
6. Agent returns results
7. Orchestrator feeds results to Planner
8. Planner updates plan
9. Loop continues until exploitation completes
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..storage.state_store import StateStore
    from ..storage.evidence_ledger import EvidenceLedger


class WorkflowPhase(str, Enum):
    """Workflow phases."""
    INIT = "init"
    PLANNING = "planning"
    AWAITING_APPROVAL = "awaiting_approval"
    EXECUTING = "executing"
    REVIEWING = "reviewing"
    COMPLETED = "completed"
    STOPPED = "stopped"


class TaskType(str, Enum):
    """Types of tasks that can be executed."""
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    VERIFICATION = "verification"


class TaskStatus(str, Enum):
    """Status of a task."""
    PENDING = "pending"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlanStep:
    """A step in the execution plan."""
    step_id: str
    order: int
    task_type: TaskType
    description: str
    target: str
    agent: str  # Which agent will execute this
    parameters: Dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "order": self.order,
            "task_type": self.task_type.value,
            "description": self.description,
            "target": self.target,
            "agent": self.agent,
            "parameters": self.parameters,
            "requires_approval": self.requires_approval,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "evidence_ids": self.evidence_ids,
        }


@dataclass
class ExecutionPlan:
    """Execution plan created by Planner."""
    plan_id: str
    version: int
    target: str
    steps: List[PlanStep]
    created_at: str
    updated_at: str
    rationale: str
    risk_assessment: str
    estimated_success_rate: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "version": self.version,
            "target": self.target,
            "steps": [s.to_dict() for s in self.steps],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "rationale": self.rationale,
            "risk_assessment": self.risk_assessment,
            "estimated_success_rate": self.estimated_success_rate,
        }

    def get_next_pending_step(self) -> Optional[PlanStep]:
        """Get next pending or approved step."""
        for step in sorted(self.steps, key=lambda s: s.order):
            if step.status in (TaskStatus.PENDING, TaskStatus.APPROVED):
                return step
        return None

    def get_current_step(self) -> Optional[PlanStep]:
        """Get currently executing step."""
        for step in self.steps:
            if step.status == TaskStatus.IN_PROGRESS:
                return step
        return None

    def mark_step_completed(
        self,
        step_id: str,
        result: Dict[str, Any],
        evidence_ids: List[str] = None,
    ) -> None:
        """Mark a step as completed."""
        for step in self.steps:
            if step.step_id == step_id:
                step.status = TaskStatus.COMPLETED
                step.result = result
                if evidence_ids:
                    step.evidence_ids = evidence_ids
                self.updated_at = datetime.utcnow().isoformat() + "Z"
                break

    def mark_step_failed(self, step_id: str, error: str) -> None:
        """Mark a step as failed."""
        for step in self.steps:
            if step.step_id == step_id:
                step.status = TaskStatus.FAILED
                step.error = error
                self.updated_at = datetime.utcnow().isoformat() + "Z"
                break

    def is_complete(self) -> bool:
        """Check if all steps are completed or skipped."""
        return all(
            s.status in (TaskStatus.COMPLETED, TaskStatus.SKIPPED, TaskStatus.FAILED)
            for s in self.steps
        )

    def get_progress(self) -> Dict[str, int]:
        """Get progress summary."""
        return {
            "total": len(self.steps),
            "completed": sum(1 for s in self.steps if s.status == TaskStatus.COMPLETED),
            "failed": sum(1 for s in self.steps if s.status == TaskStatus.FAILED),
            "pending": sum(1 for s in self.steps if s.status == TaskStatus.PENDING),
            "in_progress": sum(1 for s in self.steps if s.status == TaskStatus.IN_PROGRESS),
        }


@dataclass
class WorkflowState:
    """State of the interactive workflow."""
    session_id: str
    target_ip: str
    phase: WorkflowPhase
    current_plan: Optional[ExecutionPlan]
    execution_history: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    created_at: str
    updated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "phase": self.phase.value,
            "current_plan": self.current_plan.to_dict() if self.current_plan else None,
            "execution_history": self.execution_history,
            "findings": self.findings,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class UserProposal:
    """A proposal presented to the user for approval."""
    proposal_id: str
    proposal_type: str  # "plan", "step", "action"
    title: str
    description: str
    details: Dict[str, Any]
    options: List[Dict[str, str]]  # Available choices
    risk_level: str
    requires_response: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "proposal_type": self.proposal_type,
            "title": self.title,
            "description": self.description,
            "details": self.details,
            "options": self.options,
            "risk_level": self.risk_level,
            "requires_response": self.requires_response,
        }


@dataclass
class UserResponse:
    """User's response to a proposal."""
    proposal_id: str
    selected_option: str
    modifications: Optional[Dict[str, Any]] = None
    comment: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


@dataclass
class AgentTaskResult:
    """Result from an agent task execution."""
    task_id: str
    agent: str
    success: bool
    result_data: Dict[str, Any]
    evidence_ids: List[str]
    observations: List[Dict[str, Any]]
    error: Optional[str] = None
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent": self.agent,
            "success": self.success,
            "result_data": self.result_data,
            "evidence_ids": self.evidence_ids,
            "observations": self.observations,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


# Callback types
PlannerCallback = Callable[[str, Dict[str, Any]], ExecutionPlan]  # (target, context) -> Plan
PlanUpdateCallback = Callable[[ExecutionPlan, AgentTaskResult], ExecutionPlan]  # (plan, result) -> UpdatedPlan
UserInteractionCallback = Callable[[UserProposal], UserResponse]  # (proposal) -> response
AgentExecutionCallback = Callable[[PlanStep, Dict[str, Any]], AgentTaskResult]  # (step, context) -> result


class InteractiveWorkflow:
    """
    Interactive workflow manager.

    Implements the step-by-step penetration testing workflow with:
    - Planner-driven execution planning
    - User approval at each decision point
    - Agent execution with result feedback
    - Continuous plan refinement
    """

    def __init__(
        self,
        session_id: str,
        state_store: "StateStore",
        evidence_ledger: "EvidenceLedger",
        planner_callback: PlannerCallback,
        plan_update_callback: PlanUpdateCallback,
        user_interaction_callback: UserInteractionCallback,
        agent_execution_callback: AgentExecutionCallback,
    ):
        """
        Initialize interactive workflow.

        Args:
            session_id: Session identifier.
            state_store: State storage.
            evidence_ledger: Evidence storage.
            planner_callback: Callback to invoke planner for initial plan.
            plan_update_callback: Callback to update plan based on results.
            user_interaction_callback: Callback for user interaction.
            agent_execution_callback: Callback to execute agent tasks.
        """
        self.session_id = session_id
        self.state_store = state_store
        self.evidence_ledger = evidence_ledger

        self._planner_callback = planner_callback
        self._plan_update_callback = plan_update_callback
        self._user_callback = user_interaction_callback
        self._agent_callback = agent_execution_callback

        self._state: Optional[WorkflowState] = None
        self._stopped = False
        self._stop_reason: Optional[str] = None
        self._pending_step_approval: Optional[str] = None  # step_id awaiting approval
        self._report_path: Optional[str] = None  # Path to generated report

    @property
    def state(self) -> Optional[WorkflowState]:
        """Get current workflow state."""
        return self._state

    @property
    def is_running(self) -> bool:
        """Check if workflow is running."""
        return (
            self._state is not None
            and not self._stopped
            and self._state.phase not in (WorkflowPhase.COMPLETED, WorkflowPhase.STOPPED)
        )

    def start(self, target_ip: str) -> UserProposal:
        """
        Start workflow with target IP.

        Step 1: User provides IP
        Step 2: Planner creates initial plan
        Step 3: Return proposal for user approval

        Args:
            target_ip: Target IP address.

        Returns:
            UserProposal with initial plan for approval.
        """
        now = datetime.utcnow().isoformat() + "Z"

        # Initialize workflow state
        self._state = WorkflowState(
            session_id=self.session_id,
            target_ip=target_ip,
            phase=WorkflowPhase.PLANNING,
            current_plan=None,
            execution_history=[],
            findings=[],
            created_at=now,
            updated_at=now,
        )

        # Get initial context from state store
        context = self._build_context()

        # Step 2: Planner creates initial plan
        initial_plan = self._planner_callback(target_ip, context)
        self._state.current_plan = initial_plan
        self._state.phase = WorkflowPhase.AWAITING_APPROVAL
        self._state.updated_at = datetime.utcnow().isoformat() + "Z"

        # Save state
        self._save_state()

        # Step 3: Create proposal for user
        return self._create_plan_proposal(initial_plan)

    def process_user_response(self, response: UserResponse) -> Optional[UserProposal]:
        """
        Process user's response and continue workflow.

        Step 4: User approves/modifies action
        Step 5-9: Execute, review, update plan, propose next

        Args:
            response: User's response to previous proposal.

        Returns:
            Next UserProposal, or None if workflow complete/stopped.
        """
        if not self._state or not self._state.current_plan:
            raise RuntimeError("Workflow not started")

        if response.selected_option == "reject":
            self._stop("User rejected plan")
            return None

        if response.selected_option == "stop":
            self._stop("User stopped workflow")
            return None

        # Handle skip option
        if response.selected_option == "skip" and self._pending_step_approval:
            # Mark the pending step as skipped
            for step in self._state.current_plan.steps:
                if step.step_id == self._pending_step_approval:
                    step.status = TaskStatus.SKIPPED
                    break
            self._pending_step_approval = None
            self._save_state()
            return self._execute_next_step()

        # Handle modifications if any
        if response.modifications:
            self._apply_modifications(response.modifications)

        # Check if we're approving a specific step that was pending
        if self._pending_step_approval and response.selected_option == "approve":
            step_id = self._pending_step_approval
            self._pending_step_approval = None

            # Find and execute the approved step
            for step in self._state.current_plan.steps:
                if step.step_id == step_id:
                    step.status = TaskStatus.APPROVED
                    return self._execute_step(step)

        # Execute next step
        return self._execute_next_step()

    def _execute_next_step(self) -> Optional[UserProposal]:
        """Execute next pending step in plan."""
        if not self._state or not self._state.current_plan:
            return None

        plan = self._state.current_plan
        next_step = plan.get_next_pending_step()

        if not next_step:
            # All steps completed
            return self._finalize_workflow()

        # If step is already APPROVED, execute it directly
        if next_step.status == TaskStatus.APPROVED:
            return self._execute_step(next_step)

        # Check if step requires approval and hasn't been approved yet
        if next_step.requires_approval and next_step.status == TaskStatus.PENDING:
            self._state.phase = WorkflowPhase.AWAITING_APPROVAL
            self._save_state()
            return self._create_step_proposal(next_step)

        # Execute the step
        return self._execute_step(next_step)

    def _execute_step(self, step: PlanStep) -> Optional[UserProposal]:
        """
        Execute a plan step.

        Step 5: Orchestrator assigns task to agent
        Step 6: Agent returns results
        Step 7: Orchestrator feeds results to Planner
        Step 8: Planner updates plan

        Args:
            step: Step to execute.

        Returns:
            Next proposal for user.
        """
        self._state.phase = WorkflowPhase.EXECUTING
        step.status = TaskStatus.IN_PROGRESS
        self._save_state()

        # Build execution context
        context = self._build_context()

        # Step 5 & 6: Execute via agent callback
        result = self._agent_callback(step, context)

        # Record in history
        self._state.execution_history.append({
            "step_id": step.step_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "result": result.to_dict(),
        })

        # Update step status
        if result.success:
            self._state.current_plan.mark_step_completed(
                step.step_id,
                result.result_data,
                result.evidence_ids,
            )
        else:
            self._state.current_plan.mark_step_failed(step.step_id, result.error or "Unknown error")

        # Step 7 & 8: Feed results to planner for plan update
        self._state.phase = WorkflowPhase.REVIEWING
        updated_plan = self._plan_update_callback(self._state.current_plan, result)

        # Check if plan was significantly updated
        plan_changed = updated_plan.version > self._state.current_plan.version
        self._state.current_plan = updated_plan
        self._save_state()

        # Step 9: Propose next action to user
        return self._propose_next_action(result, plan_changed)

    def _propose_next_action(
        self,
        last_result: AgentTaskResult,
        plan_changed: bool,
    ) -> Optional[UserProposal]:
        """Create proposal for next action based on results."""
        plan = self._state.current_plan

        # Check if exploitation succeeded
        if self._check_exploitation_success(last_result):
            return self._create_success_proposal(last_result)

        # Check if all steps done
        if plan.is_complete():
            return self._finalize_workflow()

        # If plan changed significantly, propose the updated plan
        if plan_changed:
            self._state.phase = WorkflowPhase.AWAITING_APPROVAL
            self._save_state()
            return self._create_plan_update_proposal(plan, last_result)

        # Otherwise, continue with next step
        return self._execute_next_step()

    def _finalize_workflow(self) -> Optional[UserProposal]:
        """Finalize the workflow."""
        self._state.phase = WorkflowPhase.COMPLETED
        self._save_state()

        # Generate report
        report_path = self._generate_report()

        # Create summary proposal
        return UserProposal(
            proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
            proposal_type="summary",
            title="Penetration Test Complete",
            description="All planned steps have been executed.",
            details={
                "progress": self._state.current_plan.get_progress(),
                "findings": self._state.findings,
                "execution_history_count": len(self._state.execution_history),
                "report_path": report_path,
            },
            options=[
                {"id": "finish", "label": "Finish"},
                {"id": "continue", "label": "Add more steps"},
            ],
            risk_level="info",
            requires_response=True,
        )

    def _check_exploitation_success(self, result: AgentTaskResult) -> bool:
        """Check if exploitation was successful."""
        if result.agent != "exploitation_agent":
            return False

        return result.success and result.result_data.get("exploitation_success", False)

    def _create_success_proposal(self, result: AgentTaskResult) -> UserProposal:
        """Create proposal for successful exploitation."""
        self._state.phase = WorkflowPhase.COMPLETED
        self._save_state()

        # Generate report
        report_path = self._generate_report()

        return UserProposal(
            proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
            proposal_type="success",
            title="Exploitation Successful!",
            description="The target has been successfully compromised.",
            details={
                "result": result.result_data,
                "evidence_ids": result.evidence_ids,
                "method": result.result_data.get("method", "Unknown"),
                "report_path": report_path,
            },
            options=[
                {"id": "document", "label": "Document findings and finish"},
                {"id": "escalate", "label": "Attempt privilege escalation"},
            ],
            risk_level="critical",
            requires_response=True,
        )

    def _create_plan_proposal(self, plan: ExecutionPlan) -> UserProposal:
        """Create proposal for initial plan approval."""
        steps_summary = []
        for step in sorted(plan.steps, key=lambda s: s.order):
            steps_summary.append({
                "order": step.order,
                "type": step.task_type.value,
                "description": step.description,
                "agent": step.agent,
                "requires_approval": step.requires_approval,
            })

        return UserProposal(
            proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
            proposal_type="plan",
            title=f"Penetration Test Plan for {plan.target}",
            description=plan.rationale,
            details={
                "plan_id": plan.plan_id,
                "steps": steps_summary,
                "estimated_success_rate": plan.estimated_success_rate,
                "risk_assessment": plan.risk_assessment,
            },
            options=[
                {"id": "approve", "label": "Approve and start execution"},
                {"id": "modify", "label": "Modify plan"},
                {"id": "reject", "label": "Reject and stop"},
            ],
            risk_level=plan.risk_assessment,
        )

    def _create_step_proposal(self, step: PlanStep) -> UserProposal:
        """Create proposal for step approval."""
        # Track which step is pending approval
        self._pending_step_approval = step.step_id
        return UserProposal(
            proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
            proposal_type="step",
            title=f"Approve Step: {step.description}",
            description=f"This step requires your approval before execution.",
            details={
                "step_id": step.step_id,
                "task_type": step.task_type.value,
                "target": step.target,
                "agent": step.agent,
                "parameters": step.parameters,
            },
            options=[
                {"id": "approve", "label": "Approve and execute"},
                {"id": "skip", "label": "Skip this step"},
                {"id": "modify", "label": "Modify parameters"},
                {"id": "stop", "label": "Stop workflow"},
            ],
            risk_level="high" if step.requires_approval else "medium",
        )

    def _create_plan_update_proposal(
        self,
        plan: ExecutionPlan,
        last_result: AgentTaskResult,
    ) -> UserProposal:
        """Create proposal for updated plan."""
        return UserProposal(
            proposal_id=f"prop-{uuid.uuid4().hex[:8]}",
            proposal_type="plan_update",
            title="Plan Updated Based on Results",
            description=f"The plan has been updated (v{plan.version}) based on the latest findings.",
            details={
                "last_step_result": {
                    "success": last_result.success,
                    "observations_count": len(last_result.observations),
                },
                "plan_changes": plan.rationale,
                "remaining_steps": [
                    s.to_dict() for s in plan.steps
                    if s.status == TaskStatus.PENDING
                ],
                "progress": plan.get_progress(),
            },
            options=[
                {"id": "approve", "label": "Continue with updated plan"},
                {"id": "modify", "label": "Modify plan"},
                {"id": "stop", "label": "Stop here"},
            ],
            risk_level=plan.risk_assessment,
        )

    def _apply_modifications(self, modifications: Dict[str, Any]) -> None:
        """Apply user modifications to plan."""
        if not self._state or not self._state.current_plan:
            return

        plan = self._state.current_plan

        # Handle step modifications
        if "skip_steps" in modifications:
            for step_id in modifications["skip_steps"]:
                for step in plan.steps:
                    if step.step_id == step_id:
                        step.status = TaskStatus.SKIPPED

        # Handle parameter modifications
        if "step_parameters" in modifications:
            for step_id, params in modifications["step_parameters"].items():
                for step in plan.steps:
                    if step.step_id == step_id:
                        step.parameters.update(params)

        plan.updated_at = datetime.utcnow().isoformat() + "Z"
        self._save_state()

    def _build_context(self) -> Dict[str, Any]:
        """Build context for planner/agents."""
        context = {
            "session_id": self.session_id,
            "target_ip": self._state.target_ip if self._state else None,
        }

        # Add state data
        try:
            context["scope"] = self.state_store.read_json("scope.json")
            context["target_profile"] = self.state_store.read_json("target_profile.json")
            context["observations"] = list(self.state_store.read_jsonl("observations.jsonl"))
            context["vuln_candidates"] = self.state_store.read_json("candidates_vuln.json")
        except Exception:
            pass

        # Add execution history
        if self._state:
            context["execution_history"] = self._state.execution_history
            context["findings"] = self._state.findings

        return context

    def _save_state(self) -> None:
        """Save workflow state to state store."""
        if self._state:
            self.state_store.write_json("workflow_state.json", self._state.to_dict())

    def _generate_report(self) -> Optional[str]:
        """Generate a report for the completed workflow."""
        if not self._state:
            return None

        try:
            from ..cli.report_generator import ReportGenerator

            generator = ReportGenerator()
            report_path = generator.generate_report(
                workflow_state=self._state,
                evidence_ledger=self.evidence_ledger,
            )
            self._report_path = report_path
            return report_path
        except Exception as e:
            # Log error but don't fail the workflow
            print(f"Warning: Failed to generate report: {e}")
            return None

    def _stop(self, reason: str) -> None:
        """Stop the workflow."""
        self._stopped = True
        self._stop_reason = reason
        if self._state:
            self._state.phase = WorkflowPhase.STOPPED
            self._save_state()

    def get_status(self) -> Dict[str, Any]:
        """Get workflow status."""
        return {
            "session_id": self.session_id,
            "is_running": self.is_running,
            "stopped": self._stopped,
            "stop_reason": self._stop_reason,
            "phase": self._state.phase.value if self._state else None,
            "progress": self._state.current_plan.get_progress() if self._state and self._state.current_plan else None,
            "report_path": self._report_path,
        }
