"""
Display utilities for CLI.

Provides formatted output for the command-line interface.

FR-2: Natural language summary mode - hides technical commands,
shows human-readable descriptions only.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.phase_brief import PhaseBrief, PhaseType, RiskLevel
    from ..schemas.test_plan import TestPlan, PhaseStatus
    from ..orchestrator.phase_approval import PhaseApprovalRequest
    from ..orchestrator.escalation import EscalationRequest
    from ..orchestrator.override import OverrideRequest


class Display:
    """Display utilities for CLI output."""

    # ANSI color codes
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
        "white": "\033[37m",
    }

    def __init__(self, use_colors: bool = True):
        """
        Initialize display.

        Args:
            use_colors: Whether to use ANSI colors.
        """
        self.use_colors = use_colors

    def _color(self, text: str, color: str) -> str:
        """Apply color to text."""
        if not self.use_colors:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def header(self, text: str) -> str:
        """Format header text."""
        line = "=" * len(text)
        return f"\n{self._color(line, 'cyan')}\n{self._color(text, 'bold')}\n{self._color(line, 'cyan')}\n"

    def subheader(self, text: str) -> str:
        """Format subheader text."""
        return f"\n{self._color('--- ' + text + ' ---', 'blue')}\n"

    def success(self, text: str) -> str:
        """Format success message."""
        return f"{self._color('[+]', 'green')} {text}"

    def error(self, text: str) -> str:
        """Format error message."""
        return f"{self._color('[-]', 'red')} {text}"

    def warning(self, text: str) -> str:
        """Format warning message."""
        return f"{self._color('[!]', 'yellow')} {text}"

    def info(self, text: str) -> str:
        """Format info message."""
        return f"{self._color('[*]', 'blue')} {text}"

    def phase(self, phase_name: str, status: str = "") -> str:
        """Format phase display."""
        phase_color = "cyan"
        status_str = f" ({status})" if status else ""
        return f"\n{self._color('Phase:', 'bold')} {self._color(phase_name, phase_color)}{status_str}\n"

    def progress(self, current: int, total: int, width: int = 40) -> str:
        """Format progress bar."""
        if total == 0:
            percent = 0
        else:
            percent = current / total

        filled = int(width * percent)
        bar = "█" * filled + "░" * (width - filled)
        return f"[{bar}] {current}/{total} ({percent*100:.1f}%)"

    def table(
        self,
        headers: List[str],
        rows: List[List[str]],
        alignments: Optional[List[str]] = None,
    ) -> str:
        """
        Format a table.

        Args:
            headers: Column headers.
            rows: Table rows.
            alignments: Column alignments ('l', 'c', 'r').

        Returns:
            Formatted table string.
        """
        if not rows:
            return ""

        # Calculate column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))

        # Default alignments
        if not alignments:
            alignments = ["l"] * len(headers)

        # Build table
        lines = []

        # Header
        header_line = " | ".join(
            self._align(h, widths[i], alignments[i])
            for i, h in enumerate(headers)
        )
        lines.append(self._color(header_line, "bold"))

        # Separator
        sep = "-+-".join("-" * w for w in widths)
        lines.append(sep)

        # Rows
        for row in rows:
            row_line = " | ".join(
                self._align(str(cell) if i < len(row) else "", widths[i], alignments[i])
                for i, cell in enumerate(row + [""] * (len(headers) - len(row)))
            )
            lines.append(row_line)

        return "\n".join(lines)

    def _align(self, text: str, width: int, alignment: str) -> str:
        """Align text within width."""
        if alignment == "r":
            return text.rjust(width)
        elif alignment == "c":
            return text.center(width)
        else:
            return text.ljust(width)

    def key_value(self, items: Dict[str, Any], indent: int = 0) -> str:
        """
        Format key-value pairs.

        Args:
            items: Dictionary of items.
            indent: Indentation level.

        Returns:
            Formatted string.
        """
        prefix = "  " * indent
        lines = []
        for key, value in items.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{self._color(key + ':', 'bold')}")
                lines.append(self.key_value(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}{self._color(key + ':', 'bold')}")
                for item in value:
                    lines.append(f"{prefix}  - {item}")
            else:
                lines.append(
                    f"{prefix}{self._color(key + ':', 'bold')} {value}"
                )
        return "\n".join(lines)

    def approval_request(
        self,
        operation: str,
        target: str,
        risk_level: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Format approval request display."""
        lines = [
            self.header("APPROVAL REQUIRED"),
            "",
            f"{self._color('Operation:', 'bold')} {operation}",
            f"{self._color('Target:', 'bold')} {target}",
            f"{self._color('Risk Level:', 'bold')} {self._color(risk_level.upper(), 'red' if risk_level in ('high', 'critical') else 'yellow')}",
        ]

        if details:
            lines.append("")
            lines.append(self._color("Details:", "bold"))
            for key, value in details.items():
                lines.append(f"  {key}: {value}")

        lines.append("")
        lines.append(self._color("Do you approve this operation? [y/N]", "yellow"))

        return "\n".join(lines)

    def status_display(self, status: Dict[str, Any]) -> str:
        """Format orchestrator status display."""
        lines = [
            self.subheader("Orchestrator Status"),
            f"  Session ID: {status.get('session_id', 'N/A')}",
            f"  Scope Tag: {status.get('scope_tag', 'N/A')}",
            f"  Current Phase: {self._color(status.get('current_phase', 'N/A'), 'cyan')}",
            f"  Running: {self._color('Yes', 'green') if status.get('is_running') else self._color('No', 'red')}",
            f"  State Version: {status.get('state_version', 0)}",
            f"  Pending Approvals: {status.get('pending_approvals', 0)}",
            f"  Audit Events: {status.get('audit_events_count', 0)}",
        ]

        stop_status = status.get("stop_monitor_status", {})
        if stop_status.get("should_stop"):
            lines.append(f"  {self._color('STOPPED:', 'red')} {stop_status.get('stop_reason', 'Unknown')}")

        return "\n".join(lines)

    def finding_display(self, finding: Dict[str, Any]) -> str:
        """Format a finding for display."""
        severity = finding.get("severity", "unknown")
        severity_colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "cyan",
        }
        color = severity_colors.get(severity.lower(), "white")

        lines = [
            f"  {self._color('Title:', 'bold')} {finding.get('title', 'N/A')}",
            f"  {self._color('Severity:', 'bold')} {self._color(severity.upper(), color)}",
            f"  {self._color('Affected:', 'bold')} {finding.get('affected_component', 'N/A')}",
        ]

        if finding.get("description"):
            lines.append(f"  {self._color('Description:', 'bold')} {finding['description'][:100]}...")

        return "\n".join(lines)

    def spinner_frames(self) -> List[str]:
        """Get spinner animation frames."""
        return ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    # ============================================================
    # FR-2: Natural Language Summary Mode
    # ============================================================

    def phase_brief_display(self, brief: "PhaseBrief") -> str:
        """
        Display a phase brief in natural language.

        NO technical commands shown - only human-readable summaries.
        """
        risk_color = self._get_risk_color(brief.overall_risk_level.value)

        lines = [
            self.header(f"Phase: {brief.title}"),
            "",
            f"{self._color('Objective:', 'bold')} {brief.objective}",
            "",
            f"{self._color('Why:', 'bold')} {brief.rationale}",
            "",
            f"{self._color('Risk Level:', 'bold')} {self._color(brief.overall_risk_level.value.upper(), risk_color)}",
            "",
        ]

        # Planned actions - natural language only
        if brief.planned_actions:
            lines.append(self._color("What will be done:", "bold"))
            for i, action in enumerate(brief.planned_actions, 1):
                approval_marker = " ⚠️" if getattr(action, 'requires_approval', False) else ""
                risk_marker = f" [{action.risk_level.value}]" if action.risk_level else ""
                lines.append(f"  {i}. {action.summary}{risk_marker}{approval_marker}")
                if action.objective:
                    lines.append(f"     Goal: {action.objective}")
            lines.append("")

        # Risk notes
        if brief.risk_notes:
            lines.append(self._color("Risk Notes:", "bold"))
            for note in brief.risk_notes:
                lines.append(f"  • {note}")
            lines.append("")

        # Safety constraints
        if brief.safety_constraints:
            lines.append(self._color("Safety Measures:", "bold"))
            for constraint in brief.safety_constraints:
                lines.append(f"  ✓ {constraint.description}")
            lines.append("")

        # Expected outcomes
        if brief.expected_outcomes:
            lines.append(self._color("Expected Outcomes:", "bold"))
            for outcome in brief.expected_outcomes:
                lines.append(f"  → {outcome}")
            lines.append("")

        return "\n".join(lines)

    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level."""
        colors = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }
        return colors.get(risk_level.lower(), "white")

    def phase_approval_display(self, request: "PhaseApprovalRequest") -> str:
        """
        Display a phase approval request in natural language.

        For FR-1: Phase boundary approval display.
        """
        lines = [
            self.header("PHASE APPROVAL REQUIRED"),
            "",
        ]

        # Add brief display
        lines.append(self.phase_brief_display(request.brief))

        # Add test plan diff if available
        if request.test_plan_diff:
            lines.extend([
                self._color("Test Plan Updates:", "bold"),
                request.test_plan_diff,
                "",
            ])

        # Options
        lines.extend([
            self._color("Options:", "bold"),
            f"  {self._color('[A]', 'green')} Approve and proceed",
            f"  {self._color('[R]', 'red')} Reject and stop",
            f"  {self._color('[D]', 'yellow')} Defer (hold for later)",
            "",
        ])

        return "\n".join(lines)

    def escalation_display(self, request: "EscalationRequest") -> str:
        """
        Display an escalation request in natural language.

        For FR-3: Policy escalation display.
        """
        severity_color = self._get_risk_color(request.severity.value)

        lines = [
            self.header("ESCALATION REQUIRED"),
            "",
            f"{self._color('Type:', 'bold')} {request.escalation_type.value.replace('_', ' ').title()}",
            f"{self._color('Severity:', 'bold')} {self._color(request.severity.value.upper(), severity_color)}",
            "",
            f"{self._color('Issue:', 'bold')} {request.reason}",
            "",
        ]

        # Context
        if hasattr(request, 'context') and request.context:
            lines.append(self._color("Context:", "bold"))
            ctx = request.context
            if hasattr(ctx, 'phase') and ctx.phase:
                lines.append(f"  Phase: {ctx.phase}")
            if hasattr(ctx, 'agent') and ctx.agent:
                lines.append(f"  Agent: {ctx.agent}")
            if hasattr(ctx, 'operation_description') and ctx.operation_description:
                lines.append(f"  Operation: {ctx.operation_description}")
            lines.append("")

        # Recommended actions
        if hasattr(request, 'recommended_action') and request.recommended_action:
            lines.extend([
                self._color("Recommended Action:", "bold"),
                f"  {request.recommended_action}",
                "",
            ])

        # Options
        lines.extend([
            self._color("Options:", "bold"),
            f"  {self._color('[P]', 'green')} Approve and proceed",
            f"  {self._color('[M]', 'yellow')} Modify (provide alternative)",
            f"  {self._color('[S]', 'red')} Stop execution",
            "",
        ])

        return "\n".join(lines)

    def override_display(self, request: "OverrideRequest") -> str:
        """
        Display an override request in natural language.

        For FR-4: Override functionality display.
        """
        stop_report = request.stop_report

        lines = [
            self.header("OVERRIDE REQUESTED"),
            "",
        ]

        # Stop information
        if stop_report.can_override:
            lines.append(f"{self._color('Status:', 'bold')} {self._color('Override Possible', 'yellow')}")
        else:
            lines.append(f"{self._color('Status:', 'bold')} {self._color('CANNOT BE OVERRIDDEN', 'red')}")
            lines.append("")
            lines.append(self._color("This operation is blocked by security policy.", "red"))
            lines.append("Please choose an alternative approach.")
            return "\n".join(lines)

        lines.extend([
            "",
            f"{self._color('Why Stopped:', 'bold')} {stop_report.stop_reason}",
            f"{self._color('Category:', 'bold')} {stop_report.stop_category.replace('_', ' ').title()}",
            "",
        ])

        # Impact
        if stop_report.impact_if_continue:
            lines.extend([
                self._color("Impact if Override Granted:", "bold"),
                f"  {stop_report.impact_if_continue}",
                "",
            ])

        # Alternatives
        if stop_report.alternatives:
            lines.append(self._color("Alternative Approaches:", "bold"))
            for i, alt in enumerate(stop_report.alternatives, 1):
                lines.append(f"  {i}. {alt}")
            lines.append("")

        # Recommendation
        if stop_report.recommendation:
            lines.extend([
                self._color("Recommendation:", "bold"),
                f"  {stop_report.recommendation}",
                "",
            ])

        # Risk acknowledgment
        lines.extend([
            self._color("Risk Acknowledgment Required:", "yellow"),
            f"  {request.risk_acknowledgment}",
            "",
        ])

        # Options
        lines.extend([
            self._color("Options:", "bold"),
            f"  {self._color('[O]', 'yellow')} Override and continue (requires acknowledgment)",
            f"  {self._color('[C]', 'green')} Cancel and stop",
            f"  {self._color('[A]', 'blue')} Choose an alternative",
            "",
        ])

        return "\n".join(lines)

    def test_plan_summary(self, test_plan: "TestPlan") -> str:
        """
        Display test plan summary in natural language.

        For FR-2: Human-readable test plan summary.
        """
        lines = [
            self.header(f"Test Plan v{test_plan.version}"),
            "",
            f"{self._color('Target:', 'bold')} {test_plan.target_description}",
            f"{self._color('Scope:', 'bold')} {test_plan.scope_summary}",
            "",
            f"{self._color('Objective:', 'bold')} {test_plan.primary_objective}",
            "",
        ]

        # Phase progress
        lines.append(self._color("Progress:", "bold"))
        status_icons = {
            "not_started": "⬜",
            "in_progress": "🔄",
            "completed": "✅",
            "skipped": "⏭️",
            "blocked": "🚫",
            "failed": "❌",
        }

        for phase_obj in test_plan.phase_sequence:
            icon = status_icons.get(phase_obj.status.value, "⬜")
            phase_name = phase_obj.phase.value.replace("_", " ").title()
            lines.append(f"  {icon} {phase_name}")
            if phase_obj.notes:
                lines.append(f"     {self._color(phase_obj.notes, 'dim')}")

        lines.append("")

        # Current phase
        if test_plan.current_phase:
            lines.append(
                f"{self._color('Current Phase:', 'bold')} "
                f"{test_plan.current_phase.value.replace('_', ' ').title()}"
            )
            lines.append("")

        # Open questions
        unresolved = [q for q in test_plan.open_questions if not q.resolved]
        if unresolved:
            lines.append(self._color(f"Open Questions ({len(unresolved)}):", "bold"))
            for q in unresolved[:3]:
                priority_color = {"high": "red", "medium": "yellow", "low": "blue"}.get(q.priority, "white")
                lines.append(f"  • [{self._color(q.priority, priority_color)}] {q.question}")
            lines.append("")

        # Recent changes
        if test_plan.change_log:
            lines.append(self._color("Recent Updates:", "bold"))
            for change in test_plan.change_log[-3:]:
                lines.append(f"  • {change.summary}")
            lines.append("")

        # Risk level
        risk_color = self._get_risk_color(test_plan.overall_risk_level.value)
        lines.append(
            f"{self._color('Risk Level:', 'bold')} "
            f"{self._color(test_plan.overall_risk_level.value.upper(), risk_color)}"
        )

        return "\n".join(lines)

    def action_summary(
        self,
        action: str,
        outcome: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Display action summary in natural language.

        For FR-2: Shows what was done, not the command.
        """
        status_icon = self._color("✓", "green") if success else self._color("✗", "red")

        lines = [
            f"{status_icon} {self._color(action, 'bold')}",
            f"   {outcome}",
        ]

        if details:
            for key, value in details.items():
                # Convert key to human-readable
                human_key = key.replace("_", " ").title()
                lines.append(f"   {human_key}: {value}")

        return "\n".join(lines)

    def progress_summary(
        self,
        phase: str,
        completed_actions: int,
        total_actions: int,
        findings: int = 0,
    ) -> str:
        """
        Display progress summary in natural language.

        For FR-2: Human-readable progress update.
        """
        percent = (completed_actions / total_actions * 100) if total_actions > 0 else 0

        lines = [
            self.subheader(f"{phase} Progress"),
            f"  {self.progress(completed_actions, total_actions)}",
        ]

        if findings > 0:
            lines.append(f"  {self._color('Findings:', 'bold')} {findings} items discovered")

        return "\n".join(lines)

    def waiting_display(self, message: str, reason: Optional[str] = None) -> str:
        """
        Display a waiting message.

        For FR-2: Clear indication of what the system is waiting for.
        """
        lines = [
            "",
            f"  {self._color('⏳', 'yellow')} {message}",
        ]

        if reason:
            lines.append(f"     {self._color(reason, 'dim')}")

        return "\n".join(lines)
