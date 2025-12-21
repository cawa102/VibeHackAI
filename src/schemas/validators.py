"""
Validators for PentestAgent schemas.

Provides validation functions for cross-schema validation and
evidence requirements.
"""

from __future__ import annotations

from typing import List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from .finding_candidate import FindingCandidate, FindingSeverity
    from .scope import Scope, TargetType


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


class EvidenceValidationError(ValidationError):
    """Raised when evidence validation fails."""
    pass


class ScopeValidationError(ValidationError):
    """Raised when scope validation fails."""
    pass


def validate_evidence_ids(
    evidence_ids: List[str],
    existing_evidence_ids: Set[str],
    min_required: int = 1,
    context: str = "object"
) -> None:
    """
    Validate that evidence IDs exist in the evidence store.

    Args:
        evidence_ids: List of evidence IDs to validate.
        existing_evidence_ids: Set of known existing evidence IDs.
        min_required: Minimum number of evidence items required.
        context: Context for error messages.

    Raises:
        EvidenceValidationError: If validation fails.
    """
    if len(evidence_ids) < min_required:
        raise EvidenceValidationError(
            f"{context} requires at least {min_required} evidence item(s), "
            f"got {len(evidence_ids)}"
        )

    missing = set(evidence_ids) - existing_evidence_ids
    if missing:
        raise EvidenceValidationError(
            f"Evidence IDs not found: {', '.join(sorted(missing))}"
        )


def validate_scope_tag(
    scope_tag: str,
    scope: "Scope",
    target_type: Optional["TargetType"] = None
) -> None:
    """
    Validate that a scope tag is within the allowed scope.

    Args:
        scope_tag: The scope tag to validate.
        scope: The Scope object to validate against.
        target_type: Optional target type for more specific validation.

    Raises:
        ScopeValidationError: If validation fails.
    """
    from .scope import TargetType

    if scope.is_expired():
        raise ScopeValidationError("Scope has expired")

    # Try to determine target type if not provided
    if target_type is None:
        # Simple heuristics
        if "/" in scope_tag and "." in scope_tag.split("/")[0]:
            target_type = TargetType.CIDR
        elif scope_tag.replace(".", "").isdigit():
            target_type = TargetType.IP
        elif scope_tag.startswith("http"):
            target_type = TargetType.URL
        else:
            target_type = TargetType.DOMAIN

    if not scope.is_target_allowed(scope_tag, target_type):
        raise ScopeValidationError(
            f"Target '{scope_tag}' is not within the allowed scope"
        )


def validate_finding_evidence_requirement(
    severity: "FindingSeverity",
    evidence_ids: List[str],
    existing_evidence_ids: Optional[Set[str]] = None
) -> None:
    """
    Validate that a finding has sufficient evidence for its severity.

    Args:
        severity: The finding severity.
        evidence_ids: List of evidence IDs.
        existing_evidence_ids: Optional set of known existing evidence IDs.

    Raises:
        EvidenceValidationError: If validation fails.
    """
    from .finding_candidate import FindingSeverity

    # Determine minimum evidence required
    if severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL):
        min_required = 2
    else:
        min_required = 1

    if len(evidence_ids) < min_required:
        raise EvidenceValidationError(
            f"{severity.value} severity findings require at least {min_required} "
            f"evidence item(s), got {len(evidence_ids)}"
        )

    # Validate evidence exists if we have the set of existing IDs
    if existing_evidence_ids is not None:
        validate_evidence_ids(
            evidence_ids,
            existing_evidence_ids,
            min_required=min_required,
            context=f"{severity.value} severity finding"
        )


def validate_execution_plan_approval(
    plan_approved: bool,
    step_requires_approval: bool,
    step_index: int
) -> None:
    """
    Validate that execution can proceed based on approval status.

    Args:
        plan_approved: Whether the overall plan is approved.
        step_requires_approval: Whether the specific step requires approval.
        step_index: Index of the step being validated.

    Raises:
        ValidationError: If execution should not proceed.
    """
    if step_requires_approval and not plan_approved:
        raise ValidationError(
            f"Step {step_index} requires approval but plan is not approved"
        )


def validate_vuln_candidate_for_exploit(
    vuln_has_evidence: bool,
    vuln_false_positive: bool,
    vuln_id: str
) -> None:
    """
    Validate that a vulnerability candidate is suitable for exploitation.

    Args:
        vuln_has_evidence: Whether the vulnerability has evidence.
        vuln_false_positive: Whether the vulnerability is marked as false positive.
        vuln_id: ID of the vulnerability.

    Raises:
        ValidationError: If vulnerability is not suitable.
    """
    if vuln_false_positive:
        raise ValidationError(
            f"Cannot create exploit for false positive vulnerability: {vuln_id}"
        )

    if not vuln_has_evidence:
        raise ValidationError(
            f"Cannot create exploit for vulnerability without evidence: {vuln_id}"
        )


def validate_id_format(id_value: str, prefix: Optional[str] = None) -> bool:
    """
    Validate ID format.

    Args:
        id_value: The ID to validate.
        prefix: Optional required prefix.

    Returns:
        True if valid, False otherwise.
    """
    if not id_value or not id_value.strip():
        return False

    if prefix and not id_value.startswith(prefix):
        return False

    return True


def validate_cvss_score(score: Optional[float]) -> bool:
    """
    Validate CVSS score is within valid range.

    Args:
        score: The CVSS score to validate.

    Returns:
        True if valid, False otherwise.
    """
    if score is None:
        return True

    return 0.0 <= score <= 10.0
