"""
Decision Trace schema for PentestAgent.

Records decision-making processes for audit and explainability.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field, validator

from .base import BaseSchema


class DecisionType(str, Enum):
    """Types of decisions."""
    PHASE_TRANSITION = "phase_transition"
    TARGET_SELECTION = "target_selection"
    TOOL_SELECTION = "tool_selection"
    VULN_PRIORITIZATION = "vuln_prioritization"
    EXPLOIT_SELECTION = "exploit_selection"
    PLAN_APPROVAL = "plan_approval"
    FINDING_PROMOTION = "finding_promotion"
    SKIP_ACTION = "skip_action"
    RETRY_ACTION = "retry_action"
    ESCALATION = "escalation"
    ABORT = "abort"
    OTHER = "other"


class DecisionOption(BaseModel):
    """An option that was considered in a decision."""

    option_id: str = Field(
        ...,
        description="Unique identifier for this option",
    )
    description: str = Field(
        ...,
        description="Description of the option",
    )
    pros: List[str] = Field(
        default_factory=list,
        description="Advantages of this option",
    )
    cons: List[str] = Field(
        default_factory=list,
        description="Disadvantages of this option",
    )
    score: Optional[float] = Field(
        None,
        description="Numeric score if applicable",
    )
    selected: bool = Field(
        default=False,
        description="Whether this option was selected",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )


class DecisionTrace(BaseSchema):
    """
    Record of a decision made during the pentest process.

    Captures what options were considered, what was selected,
    and the rationale for the decision.
    """

    decision_type: DecisionType = Field(
        ...,
        description="Type of decision",
    )
    context: str = Field(
        ...,
        description="Context/situation requiring the decision",
    )
    options: List[DecisionOption] = Field(
        default_factory=list,
        description="Options that were considered",
    )
    selected_option_id: Optional[str] = Field(
        None,
        description="ID of the selected option",
    )
    rationale: str = Field(
        ...,
        description="Rationale for the decision",
    )
    factors_considered: List[str] = Field(
        default_factory=list,
        description="Factors that influenced the decision",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence in the decision (0.0-1.0)",
    )
    automated: bool = Field(
        default=True,
        description="Whether decision was made automatically",
    )
    human_override: bool = Field(
        default=False,
        description="Whether human overrode the automated decision",
    )
    human_override_reason: Optional[str] = Field(
        None,
        description="Reason for human override",
    )
    related_ids: Dict[str, str] = Field(
        default_factory=dict,
        description="Related object IDs (vuln_id, plan_id, etc.)",
    )
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs supporting the decision",
    )
    outcome: Optional[str] = Field(
        None,
        description="Outcome of the decision (recorded after the fact)",
    )
    outcome_success: Optional[bool] = Field(
        None,
        description="Whether the outcome was successful",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes",
    )

    @validator("context")
    def validate_context(cls, v: str) -> str:
        """Validate context is not empty."""
        if not v or not v.strip():
            raise ValueError("context cannot be empty")
        return v.strip()

    @validator("rationale")
    def validate_rationale(cls, v: str) -> str:
        """Validate rationale is not empty."""
        if not v or not v.strip():
            raise ValueError("rationale cannot be empty")
        return v.strip()

    def add_option(self, option: DecisionOption) -> None:
        """Add an option to the decision."""
        self.options.append(option)

    def select_option(self, option_id: str, rationale: Optional[str] = None) -> None:
        """Select an option."""
        # Mark the selected option
        for option in self.options:
            option.selected = option.option_id == option_id

        self.selected_option_id = option_id

        if rationale:
            self.rationale = rationale

    def get_selected_option(self) -> Optional[DecisionOption]:
        """Get the selected option."""
        for option in self.options:
            if option.selected:
                return option
        return None

    def record_outcome(self, outcome: str, success: bool) -> None:
        """Record the outcome of the decision."""
        self.outcome = outcome
        self.outcome_success = success

    def override_with_human(self, new_option_id: str, reason: str) -> None:
        """Override the decision with human input."""
        self.human_override = True
        self.human_override_reason = reason
        self.select_option(new_option_id)

    @classmethod
    def create_phase_transition(
        cls,
        session_id: str,
        from_phase: str,
        to_phase: str,
        rationale: str,
        created_by: str,
        scope_tag: str,
    ) -> "DecisionTrace":
        """
        Factory method to create a phase transition decision.

        Args:
            session_id: Session ID.
            from_phase: Current phase.
            to_phase: Target phase.
            rationale: Reason for transition.
            created_by: Who made the decision.
            scope_tag: Scope tag.

        Returns:
            New DecisionTrace instance.
        """
        return cls(
            session_id=session_id,
            decision_type=DecisionType.PHASE_TRANSITION,
            context=f"Transitioning from {from_phase} to {to_phase}",
            rationale=rationale,
            created_by=created_by,
            scope_tag=scope_tag,
            options=[
                DecisionOption(
                    option_id="continue",
                    description=f"Continue to {to_phase}",
                    selected=True,
                ),
                DecisionOption(
                    option_id="stay",
                    description=f"Stay in {from_phase}",
                    selected=False,
                ),
            ],
            selected_option_id="continue",
        )
