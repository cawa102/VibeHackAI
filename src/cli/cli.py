"""
Main CLI for PentestAgent.

Provides command-line interface for interacting with the orchestrator.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING

from .display import Display
from .prompts import Prompts

if TYPE_CHECKING:
    from ..orchestrator.orchestrator import Orchestrator, OrchestratorConfig
    from ..orchestrator.approval_gate import ApprovalRequest, ApprovalResult
    from ..storage.state_store import StateStore
    from ..storage.evidence_ledger import EvidenceLedger
    from ..storage.session_manager import SessionManager


@dataclass
class CLIConfig:
    """Configuration for CLI."""
    workspace_path: str = ".pentest_workspace"
    use_colors: bool = True
    verbose: bool = False


class CLI:
    """
    Command-line interface for PentestAgent.

    Provides user interaction for:
    - Session management
    - Scope definition
    - Phase progression monitoring
    - Approval handling
    - Results display
    """

    def __init__(self, config: Optional[CLIConfig] = None):
        """
        Initialize CLI.

        Args:
            config: CLI configuration.
        """
        self.config = config or CLIConfig()
        self.display = Display(use_colors=self.config.use_colors)
        self.prompts = Prompts()

        self._session_manager: Optional["SessionManager"] = None
        self._orchestrator: Optional["Orchestrator"] = None
        self._session_id: Optional[str] = None

    def print(self, message: str) -> None:
        """Print a message."""
        print(message)

    def run(self) -> int:
        """
        Run the CLI main loop.

        Returns:
            Exit code.
        """
        self.print(self.display.header("PentestAgent CLI"))
        self.print("Type 'help' for available commands.\n")

        try:
            while True:
                try:
                    command = input("pentest> ").strip()
                    if not command:
                        continue

                    result = self._handle_command(command)
                    if result == "exit":
                        break

                except KeyboardInterrupt:
                    self.print("\n" + self.display.info("Use 'exit' to quit."))

        except EOFError:
            pass

        self._cleanup()
        return 0

    def _handle_command(self, command: str) -> Optional[str]:
        """Handle a CLI command."""
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]

        commands = {
            "help": self._cmd_help,
            "start": self._cmd_start,
            "stop": self._cmd_stop,
            "status": self._cmd_status,
            "phase": self._cmd_phase,
            "advance": self._cmd_advance,
            "run": self._cmd_run,
            "scope": self._cmd_scope,
            "findings": self._cmd_findings,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }

        handler = commands.get(cmd)
        if handler:
            return handler(args)
        else:
            self.print(self.display.error(f"Unknown command: {cmd}"))
            return None

    def _cmd_help(self, args: list) -> None:
        """Show help."""
        help_text = """
Available Commands:
  start [session_id]  - Start a new session
  stop [reason]       - Stop the current session
  status              - Show orchestrator status
  phase               - Show current phase details
  advance             - Advance to next phase
  run                 - Run current phase agent
  scope               - Show/edit scope
  findings            - List findings
  exit, quit          - Exit CLI

Session Commands:
  start               - Start new session with interactive scope setup
  start <id>          - Resume existing session
"""
        self.print(help_text)

    def _cmd_start(self, args: list) -> None:
        """Start a new session."""
        if self._orchestrator and self._orchestrator.is_running:
            self.print(self.display.warning(
                "Session already running. Use 'stop' first."
            ))
            return

        # Initialize session manager
        self._init_session_manager()

        # Check for existing session ID
        if args:
            session_id = args[0]
            # Try to resume existing session
            try:
                session_path = self._session_manager.get_session_path(session_id)
                self.print(self.display.info(f"Resuming session: {session_id}"))
                self._session_id = session_id
            except ValueError:
                self.print(self.display.error(f"Session not found: {session_id}"))
                return
        else:
            # Create new session
            session_id = self._session_manager.create_session()
            self._session_id = session_id
            self.print(self.display.success(f"Created session: {session_id}"))

            # Interactive scope setup
            scope_data = self.prompts.scope_input()
            if not scope_data.get("targets"):
                self.print(self.display.warning("No targets defined. Aborting."))
                return

            # Save scope
            state_store = self._session_manager.get_state_store(session_id)
            state_store.write_json("scope.json", scope_data)

            # Get scope tag from first target
            scope_tag = scope_data["targets"][0]["value"]

        # Initialize orchestrator
        self._init_orchestrator(session_id, scope_tag if not args else "unknown")

        # Start orchestrator
        self._orchestrator.start()
        self.print(self.display.success("Session started!"))
        self.print(self.display.phase(
            self._orchestrator.current_phase.value,
            "active"
        ))

    def _cmd_stop(self, args: list) -> None:
        """Stop the current session."""
        if not self._orchestrator:
            self.print(self.display.warning("No session running."))
            return

        reason = " ".join(args) if args else "User requested"
        self._orchestrator.stop(reason, "user")
        self.print(self.display.success("Session stopped."))

    def _cmd_status(self, args: list) -> None:
        """Show orchestrator status."""
        if not self._orchestrator:
            self.print(self.display.warning("No session running."))
            return

        status = self._orchestrator.get_status()
        self.print(self.display.status_display(status))

    def _cmd_phase(self, args: list) -> None:
        """Show current phase details."""
        if not self._orchestrator:
            self.print(self.display.warning("No session running."))
            return

        phase = self._orchestrator.current_phase
        agent = self._orchestrator.router.get_current_agent()

        self.print(self.display.phase(phase.value))
        self.print(f"  Agent: {agent or 'N/A'}")
        self.print(f"  Can Advance: {self._orchestrator.router.can_advance({})}")

    def _cmd_advance(self, args: list) -> None:
        """Advance to next phase."""
        if not self._orchestrator:
            self.print(self.display.warning("No session running."))
            return

        # Simple phase result for manual advance
        phase_result = {
            "success": True,
            "manual_advance": True,
        }

        transition = self._orchestrator.advance_phase(phase_result)
        if transition:
            self.print(self.display.success(
                f"Advanced: {transition.from_phase.value} -> {transition.to_phase.value}"
            ))
        else:
            self.print(self.display.warning("Cannot advance from current phase."))

    def _cmd_run(self, args: list) -> None:
        """Run current phase agent."""
        if not self._orchestrator:
            self.print(self.display.warning("No session running."))
            return

        agent = self._orchestrator.router.get_current_agent()
        if not agent:
            self.print(self.display.warning("No agent for current phase."))
            return

        # Check if handler is registered
        if agent not in self._orchestrator._agent_handlers:
            self.print(self.display.warning(
                f"No handler registered for {agent}. "
                "Register agent handlers before running."
            ))
            return

        self.print(self.display.info(f"Running {agent}..."))

        try:
            result = self._orchestrator.run_phase()

            if result.success:
                self.print(self.display.success(
                    f"Agent completed successfully ({result.duration_ms}ms)"
                ))
            else:
                self.print(self.display.error(
                    f"Agent failed: {result.error}"
                ))

        except RuntimeError as e:
            self.print(self.display.error(str(e)))

    def _cmd_scope(self, args: list) -> None:
        """Show or edit scope."""
        if not self._session_id or not self._session_manager:
            self.print(self.display.warning("No session running."))
            return

        state_store = self._session_manager.get_state_store(self._session_id)

        try:
            scope = state_store.read_json("scope.json")

            self.print(self.display.subheader("Current Scope"))

            if scope.get("targets"):
                self.print("\nTargets:")
                for target in scope["targets"]:
                    self.print(f"  - [{target['type']}] {target['value']}")

            if scope.get("allowed_operations"):
                self.print("\nAllowed Operations:")
                for op in scope["allowed_operations"]:
                    self.print(f"  - {op}")

        except FileNotFoundError:
            self.print(self.display.warning("No scope defined."))

    def _cmd_findings(self, args: list) -> None:
        """List findings."""
        if not self._session_id or not self._session_manager:
            self.print(self.display.warning("No session running."))
            return

        state_store = self._session_manager.get_state_store(self._session_id)

        try:
            findings = state_store.read_jsonl("finding_candidates.jsonl")

            if not findings:
                self.print(self.display.info("No findings yet."))
                return

            self.print(self.display.subheader(f"Findings ({len(findings)})"))

            for i, finding in enumerate(findings, 1):
                self.print(f"\n{i}.")
                self.print(self.display.finding_display(finding))

        except Exception:
            self.print(self.display.info("No findings yet."))

    def _cmd_exit(self, args: list) -> str:
        """Exit CLI."""
        if self._orchestrator and self._orchestrator.is_running:
            if self.prompts.confirm("Session is running. Stop it?"):
                self._orchestrator.stop("User exit", "user")

        return "exit"

    def _init_session_manager(self) -> None:
        """Initialize session manager."""
        if not self._session_manager:
            from ..storage.session_manager import SessionManager
            workspace = Path(self.config.workspace_path).resolve()
            self._session_manager = SessionManager(workspace)

    def _init_orchestrator(self, session_id: str, scope_tag: str) -> None:
        """Initialize orchestrator."""
        from ..orchestrator.orchestrator import Orchestrator, OrchestratorConfig

        state_store = self._session_manager.get_state_store(session_id)
        evidence_ledger = self._session_manager.get_evidence_ledger(session_id)

        config = OrchestratorConfig(
            session_id=session_id,
            scope_tag=scope_tag,
        )

        self._orchestrator = Orchestrator(
            state_store=state_store,
            evidence_ledger=evidence_ledger,
            config=config,
            approval_callback=self._approval_callback,
        )

    def _approval_callback(
        self,
        request: "ApprovalRequest",
    ) -> "ApprovalResult":
        """Handle approval requests."""
        from ..orchestrator.approval_gate import ApprovalResult

        approved = self.prompts.approval_prompt(
            request.operation,
            request.target,
            request.risk_level,
            request.details,
        )

        return ApprovalResult(
            request_id=request.request_id,
            approved=approved,
            responded_by="cli_user",
            reason="User response" if approved else "User denied",
        )

    def _cleanup(self) -> None:
        """Cleanup on exit."""
        if self._orchestrator and self._orchestrator.is_running:
            self._orchestrator.stop("CLI exit", "cli")

        self.print(self.display.info("Goodbye!"))


def main() -> int:
    """Main entry point."""
    cli = CLI()
    return cli.run()


if __name__ == "__main__":
    sys.exit(main())
