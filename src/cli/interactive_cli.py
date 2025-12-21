"""
Interactive CLI for PentestAgent.

Provides a step-by-step interface for penetration testing workflow.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from typing import Any, Dict, Optional

from ..orchestrator.workflow import (
    UserProposal,
    UserResponse,
    WorkflowPhase,
)


class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"


class InteractiveCLI:
    """
    Interactive command-line interface for penetration testing.

    Displays proposals to the user and collects responses.
    """

    def __init__(self, use_colors: bool = True):
        """
        Initialize CLI.

        Args:
            use_colors: Whether to use ANSI colors.
        """
        self.use_colors = use_colors and sys.stdout.isatty()

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if enabled."""
        if self.use_colors:
            return f"{color}{text}{Colors.RESET}"
        return text

    def _print_header(self, text: str) -> None:
        """Print a header."""
        print()
        print(self._color("=" * 60, Colors.CYAN))
        print(self._color(f"  {text}", Colors.BOLD))
        print(self._color("=" * 60, Colors.CYAN))
        print()

    def _print_section(self, title: str, content: Any) -> None:
        """Print a section with title and content."""
        print(self._color(f"\n{title}:", Colors.BOLD))
        if isinstance(content, dict):
            for key, value in content.items():
                print(f"  {key}: {value}")
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict):
                    print(f"  - {item.get('description', item.get('order', item))}")
                else:
                    print(f"  - {item}")
        else:
            print(f"  {content}")

    def _print_risk_level(self, level: str) -> None:
        """Print risk level with appropriate color."""
        colors = {
            "critical": Colors.RED,
            "high": Colors.RED,
            "medium": Colors.YELLOW,
            "low": Colors.GREEN,
            "info": Colors.BLUE,
        }
        color = colors.get(level.lower(), Colors.RESET)
        print(f"\n{self._color('Risk Level:', Colors.BOLD)} {self._color(level.upper(), color)}")

    def _print_options(self, options: list) -> None:
        """Print available options."""
        print(self._color("\nAvailable Actions:", Colors.BOLD))
        for i, opt in enumerate(options, 1):
            print(f"  [{i}] {opt.get('label', opt.get('id'))}")

    def display_proposal(self, proposal: UserProposal) -> None:
        """
        Display a proposal to the user.

        Args:
            proposal: Proposal to display.
        """
        # Header based on proposal type
        type_headers = {
            "plan": "PENETRATION TEST PLAN",
            "step": "STEP APPROVAL REQUIRED",
            "plan_update": "PLAN UPDATE",
            "success": "EXPLOITATION SUCCESSFUL",
            "summary": "TEST COMPLETE",
        }
        header = type_headers.get(proposal.proposal_type, "PROPOSAL")
        self._print_header(header)

        # Title and description
        print(self._color(proposal.title, Colors.BOLD))
        print()
        print(proposal.description)

        # Details based on proposal type
        if proposal.proposal_type == "plan":
            self._display_plan_details(proposal.details)
        elif proposal.proposal_type == "step":
            self._display_step_details(proposal.details)
        elif proposal.proposal_type == "plan_update":
            self._display_update_details(proposal.details)
        elif proposal.proposal_type == "success":
            self._display_success_details(proposal.details)
        elif proposal.proposal_type == "summary":
            self._display_summary_details(proposal.details)

        # Risk level
        self._print_risk_level(proposal.risk_level)

        # Options
        self._print_options(proposal.options)

    def _display_plan_details(self, details: Dict[str, Any]) -> None:
        """Display plan details."""
        print(self._color("\nPlan Steps:", Colors.BOLD))
        for step in details.get("steps", []):
            status_icon = "[ ]"
            print(f"  {step['order']}. {status_icon} {step['description']}")
            if step.get("requires_approval"):
                print(self._color("      (requires approval)", Colors.YELLOW))

        print(f"\n{self._color('Estimated Success Rate:', Colors.BOLD)} "
              f"{details.get('estimated_success_rate', 0) * 100:.0f}%")

    def _display_step_details(self, details: Dict[str, Any]) -> None:
        """Display step details."""
        self._print_section("Task Type", details.get("task_type"))
        self._print_section("Target", details.get("target"))
        self._print_section("Agent", details.get("agent"))
        if details.get("parameters"):
            self._print_section("Parameters", details["parameters"])

    def _display_update_details(self, details: Dict[str, Any]) -> None:
        """Display plan update details."""
        last_result = details.get("last_step_result", {})
        print(f"\n{self._color('Last Step Result:', Colors.BOLD)}")
        if last_result.get("success"):
            print(self._color("  Success", Colors.GREEN))
        else:
            print(self._color("  Failed", Colors.RED))
        print(f"  Observations: {last_result.get('observations_count', 0)}")

        progress = details.get("progress", {})
        print(f"\n{self._color('Progress:', Colors.BOLD)}")
        print(f"  Completed: {progress.get('completed', 0)}/{progress.get('total', 0)}")

        remaining = details.get("remaining_steps", [])
        if remaining:
            print(f"\n{self._color('Remaining Steps:', Colors.BOLD)}")
            for step in remaining:
                print(f"  - {step.get('description', 'Unknown')}")

    def _display_success_details(self, details: Dict[str, Any]) -> None:
        """Display exploitation success details."""
        print(self._color("\n*** TARGET COMPROMISED ***", Colors.GREEN))
        print(f"\nMethod: {details.get('method', 'Unknown')}")
        print(f"Evidence IDs: {', '.join(details.get('evidence_ids', []))}")

    def _display_summary_details(self, details: Dict[str, Any]) -> None:
        """Display test summary."""
        progress = details.get("progress", {})
        print(f"\n{self._color('Execution Summary:', Colors.BOLD)}")
        print(f"  Total Steps: {progress.get('total', 0)}")
        print(f"  Completed: {progress.get('completed', 0)}")
        print(f"  Failed: {progress.get('failed', 0)}")

        findings = details.get("findings", [])
        if findings:
            print(f"\n{self._color('Findings:', Colors.BOLD)}")
            for finding in findings:
                print(f"  - {finding}")

    def get_user_response(self, proposal: UserProposal) -> UserResponse:
        """
        Get user's response to a proposal.

        Args:
            proposal: Proposal to respond to.

        Returns:
            UserResponse with user's selection.
        """
        options = proposal.options

        while True:
            print()
            try:
                choice = input(self._color("Select action [1-{}]: ".format(len(options)), Colors.CYAN))

                # Parse choice
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(options):
                        selected = options[idx]
                        selected_id = selected.get("id", selected.get("label"))

                        # Get modifications if modify option selected
                        modifications = None
                        if selected_id == "modify":
                            modifications = self._get_modifications(proposal)

                        # Get optional comment
                        comment = None
                        if selected_id in ("reject", "stop"):
                            comment = input("Reason (optional): ").strip() or None

                        return UserResponse(
                            proposal_id=proposal.proposal_id,
                            selected_option=selected_id,
                            modifications=modifications,
                            comment=comment,
                        )

                print(self._color("Invalid choice. Please try again.", Colors.RED))

            except (KeyboardInterrupt, EOFError):
                print("\n")
                return UserResponse(
                    proposal_id=proposal.proposal_id,
                    selected_option="stop",
                    comment="User interrupted",
                )

    def _get_modifications(self, proposal: UserProposal) -> Dict[str, Any]:
        """Get modifications from user."""
        print(self._color("\nEnter modifications (JSON format or press Enter to skip):", Colors.BOLD))
        try:
            mod_input = input("> ").strip()
            if mod_input:
                return json.loads(mod_input)
        except json.JSONDecodeError:
            print(self._color("Invalid JSON. Modifications ignored.", Colors.YELLOW))
        return {}

    def display_status(
        self,
        phase: WorkflowPhase,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Display status message.

        Args:
            phase: Current workflow phase.
            message: Status message.
            details: Optional details.
        """
        phase_colors = {
            WorkflowPhase.INIT: Colors.BLUE,
            WorkflowPhase.PLANNING: Colors.CYAN,
            WorkflowPhase.AWAITING_APPROVAL: Colors.YELLOW,
            WorkflowPhase.EXECUTING: Colors.MAGENTA,
            WorkflowPhase.REVIEWING: Colors.CYAN,
            WorkflowPhase.COMPLETED: Colors.GREEN,
            WorkflowPhase.STOPPED: Colors.RED,
        }
        color = phase_colors.get(phase, Colors.RESET)

        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {self._color(f'[{phase.value.upper()}]', color)} {message}")

        if details:
            for key, value in details.items():
                print(f"           {key}: {value}")

    def display_error(self, message: str) -> None:
        """Display error message."""
        print(self._color(f"\nError: {message}", Colors.RED))

    def display_success(self, message: str) -> None:
        """Display success message."""
        print(self._color(f"\n{message}", Colors.GREEN))

    def confirm(self, message: str, default: bool = False) -> bool:
        """
        Ask for confirmation.

        Args:
            message: Confirmation message.
            default: Default value if user presses Enter.

        Returns:
            True if confirmed, False otherwise.
        """
        default_str = "[Y/n]" if default else "[y/N]"
        try:
            response = input(f"{message} {default_str}: ").strip().lower()
            if not response:
                return default
            return response in ("y", "yes")
        except (KeyboardInterrupt, EOFError):
            return False


def user_interaction_callback(proposal: UserProposal) -> UserResponse:
    """
    Default user interaction callback using InteractiveCLI.

    Args:
        proposal: Proposal to present to user.

    Returns:
        User's response.
    """
    cli = InteractiveCLI()
    cli.display_proposal(proposal)
    return cli.get_user_response(proposal)
