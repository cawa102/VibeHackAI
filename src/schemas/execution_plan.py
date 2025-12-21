"""
Execution Plan schema for PentestAgent.

Defines the plan for executing exploits with approval gates.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field, validator

from .base import BaseSchema


class StepType(str, Enum):
    """Types of execution steps."""
    PREPARATION = "preparation"
    VERIFICATION = "verification"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    CLEANUP = "cleanup"
    VALIDATION = "validation"


class RiskLevel(str, Enum):
    """Risk level of an action."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStep(BaseModel):
    """A single step in an execution plan."""

    step_index: int = Field(
        ...,
        ge=0,
        description="Index of this step in the plan",
    )
    title: str = Field(
        ...,
        description="Short title for the step",
    )
    description: str = Field(
        ...,
        description="Detailed description of what this step does",
    )
    step_type: StepType = Field(
        default=StepType.EXPLOITATION,
        description="Type of step",
    )
    tool: str = Field(
        ...,
        description="Tool to use (metasploit, burp, kali, etc.)",
    )
    action: str = Field(
        ...,
        description="Specific action/command to execute",
    )
    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters for the action",
    )
    requires_approval: bool = Field(
        default=True,
        description="Whether this step requires human approval",
    )
    risk_level: RiskLevel = Field(
        default=RiskLevel.MEDIUM,
        description="Risk level of this step",
    )
    expected_outcome: Optional[str] = Field(
        None,
        description="Expected outcome of this step",
    )
    success_criteria: List[str] = Field(
        default_factory=list,
        description="Criteria to determine if step succeeded",
    )
    failure_action: Optional[str] = Field(
        None,
        description="Action to take on failure (abort, skip, retry, etc.)",
    )
    rollback_steps: List[str] = Field(
        default_factory=list,
        description="Steps to rollback if needed",
    )
    timeout_seconds: int = Field(
        default=300,
        ge=0,
        description="Timeout for this step in seconds",
    )
    depends_on: List[int] = Field(
        default_factory=list,
        description="Indices of steps this depends on",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes for the tester",
    )

    @validator("title")
    def validate_title(cls, v: str) -> str:
        """Validate title is not empty."""
        if not v or not v.strip():
            raise ValueError("title cannot be empty")
        return v.strip()


class ExecutionPlan(BaseSchema):
    """
    A plan for executing an exploit or verification.

    Contains ordered steps with approval gates for dangerous operations.
    """

    title: str = Field(
        ...,
        description="Title of the execution plan",
    )
    description: str = Field(
        ...,
        description="Description of what this plan accomplishes",
    )
    vuln_candidate_id: Optional[str] = Field(
        None,
        description="Associated vulnerability candidate ID",
    )
    exploit_candidate_id: Optional[str] = Field(
        None,
        description="Associated exploit candidate ID",
    )
    target: str = Field(
        ...,
        description="Target of the execution (host:port, URL, etc.)",
    )
    steps: List[ExecutionStep] = Field(
        default_factory=list,
        description="Ordered list of execution steps",
    )
    overall_risk: RiskLevel = Field(
        default=RiskLevel.MEDIUM,
        description="Overall risk level of the plan",
    )
    requires_approval: bool = Field(
        default=True,
        description="Whether any step requires approval",
    )
    approved: bool = Field(
        default=False,
        description="Whether the plan has been approved",
    )
    approved_by: Optional[str] = Field(
        None,
        description="Who approved the plan",
    )
    approved_at: Optional[str] = Field(
        None,
        description="When the plan was approved",
    )
    prerequisites: List[str] = Field(
        default_factory=list,
        description="Prerequisites before execution",
    )
    rollback_plan: Optional[str] = Field(
        None,
        description="Overall rollback plan",
    )
    estimated_duration_seconds: Optional[int] = Field(
        None,
        ge=0,
        description="Estimated total duration",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization",
    )

    @validator("title")
    def validate_title_plan(cls, v: str) -> str:
        """Validate title is not empty."""
        if not v or not v.strip():
            raise ValueError("title cannot be empty")
        return v.strip()

    def get_step(self, index: int) -> Optional[ExecutionStep]:
        """Get a step by index."""
        for step in self.steps:
            if step.step_index == index:
                return step
        return None

    def add_step(self, step: ExecutionStep) -> None:
        """Add a step to the plan."""
        self.steps.append(step)
        self._update_approval_requirement()

    def _update_approval_requirement(self) -> None:
        """Update overall approval requirement based on steps."""
        self.requires_approval = any(step.requires_approval for step in self.steps)

    def get_approval_required_steps(self) -> List[ExecutionStep]:
        """Get all steps that require approval."""
        return [step for step in self.steps if step.requires_approval]

    def approve(self, approved_by: str) -> None:
        """Approve the plan."""
        from datetime import datetime
        self.approved = True
        self.approved_by = approved_by
        self.approved_at = datetime.utcnow().isoformat() + "Z"

    def get_high_risk_steps(self) -> List[ExecutionStep]:
        """Get all high/critical risk steps."""
        return [
            step for step in self.steps
            if step.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ]

    def calculate_overall_risk(self) -> RiskLevel:
        """Calculate overall risk based on steps."""
        if not self.steps:
            return RiskLevel.LOW

        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        max_risk = RiskLevel.LOW

        for step in self.steps:
            if risk_order.index(step.risk_level) > risk_order.index(max_risk):
                max_risk = step.risk_level

        self.overall_risk = max_risk
        return max_risk
