"""Tests for main CLI."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from src.cli.cli import CLI, CLIConfig


class TestCLIConfig:
    """Tests for CLIConfig dataclass."""

    def test_create_config(self):
        """Test creating CLI config."""
        config = CLIConfig(
            workspace_path="/tmp/workspace",
            use_colors=False,
            verbose=True,
        )

        assert config.workspace_path == "/tmp/workspace"
        assert config.use_colors is False
        assert config.verbose is True

    def test_config_defaults(self):
        """Test config default values."""
        config = CLIConfig()

        assert config.workspace_path == ".pentest_workspace"
        assert config.use_colors is True
        assert config.verbose is False


class TestCLI:
    """Tests for CLI class."""

    @pytest.fixture
    def cli(self):
        """Create CLI instance."""
        config = CLIConfig(use_colors=False)
        return CLI(config)

    def test_initialization(self, cli):
        """Test CLI initialization."""
        assert cli.config is not None
        assert cli.display is not None
        assert cli.prompts is not None

    def test_print(self, cli, capsys):
        """Test print method."""
        cli.print("Hello")

        captured = capsys.readouterr()
        assert "Hello" in captured.out


class TestCLICommands:
    """Tests for CLI command handling."""

    @pytest.fixture
    def cli(self):
        """Create CLI instance."""
        config = CLIConfig(use_colors=False)
        return CLI(config)

    def test_handle_help(self, cli, capsys):
        """Test help command."""
        cli._handle_command("help")

        captured = capsys.readouterr()
        assert "Available Commands" in captured.out
        assert "start" in captured.out
        assert "stop" in captured.out

    def test_handle_exit(self, cli):
        """Test exit command."""
        result = cli._handle_command("exit")
        assert result == "exit"

    def test_handle_quit(self, cli):
        """Test quit command."""
        result = cli._handle_command("quit")
        assert result == "exit"

    def test_handle_unknown_command(self, cli, capsys):
        """Test unknown command."""
        cli._handle_command("foobar")

        captured = capsys.readouterr()
        assert "Unknown command" in captured.out

    def test_handle_status_no_session(self, cli, capsys):
        """Test status without session."""
        cli._handle_command("status")

        captured = capsys.readouterr()
        assert "No session" in captured.out

    def test_handle_phase_no_session(self, cli, capsys):
        """Test phase without session."""
        cli._handle_command("phase")

        captured = capsys.readouterr()
        assert "No session" in captured.out

    def test_handle_advance_no_session(self, cli, capsys):
        """Test advance without session."""
        cli._handle_command("advance")

        captured = capsys.readouterr()
        assert "No session" in captured.out

    def test_handle_run_no_session(self, cli, capsys):
        """Test run without session."""
        cli._handle_command("run")

        captured = capsys.readouterr()
        assert "No session" in captured.out

    def test_handle_scope_no_session(self, cli, capsys):
        """Test scope without session."""
        cli._handle_command("scope")

        captured = capsys.readouterr()
        assert "No session" in captured.out

    def test_handle_findings_no_session(self, cli, capsys):
        """Test findings without session."""
        cli._handle_command("findings")

        captured = capsys.readouterr()
        assert "No session" in captured.out

    def test_handle_stop_no_session(self, cli, capsys):
        """Test stop without session."""
        cli._handle_command("stop")

        captured = capsys.readouterr()
        assert "No session" in captured.out


class TestCLISessionManagement:
    """Tests for CLI session management."""

    @pytest.fixture
    def cli(self):
        """Create CLI instance."""
        config = CLIConfig(
            workspace_path="/tmp/test_workspace",
            use_colors=False,
        )
        return CLI(config)

    def test_init_session_manager(self, cli):
        """Test session manager initialization."""
        with patch("src.cli.cli.SessionManager") as MockSessionManager:
            cli._init_session_manager()

            assert cli._session_manager is not None

    @patch("src.cli.cli.SessionManager")
    @patch("src.cli.cli.Orchestrator")
    def test_start_new_session(self, MockOrchestrator, MockSessionManager, cli, capsys):
        """Test starting a new session."""
        mock_session_mgr = MagicMock()
        mock_session_mgr.create_session.return_value = "test-session-001"
        mock_state_store = MagicMock()
        mock_state_store.read_json.return_value = {}
        mock_session_mgr.get_state_store.return_value = mock_state_store
        mock_session_mgr.get_evidence_ledger.return_value = MagicMock()
        MockSessionManager.return_value = mock_session_mgr

        mock_orchestrator = MagicMock()
        mock_orchestrator.is_running = False
        MockOrchestrator.return_value = mock_orchestrator

        # Mock scope input to return empty
        cli.prompts.scope_input = MagicMock(return_value={"targets": []})

        cli._handle_command("start")

        captured = capsys.readouterr()
        # Should warn about no targets
        assert "No targets" in captured.out or "Created session" in captured.out

    @patch("src.cli.cli.SessionManager")
    def test_start_resume_session(self, MockSessionManager, cli, capsys):
        """Test resuming existing session."""
        mock_session_mgr = MagicMock()
        mock_session_mgr.get_session_path.return_value = "/tmp/session"
        MockSessionManager.return_value = mock_session_mgr

        cli._init_session_manager()
        cli._handle_command("start existing-session-id")

        captured = capsys.readouterr()
        assert "Resuming session" in captured.out

    @patch("src.cli.cli.SessionManager")
    def test_start_invalid_session(self, MockSessionManager, cli, capsys):
        """Test resuming non-existent session."""
        mock_session_mgr = MagicMock()
        mock_session_mgr.get_session_path.side_effect = ValueError("Not found")
        MockSessionManager.return_value = mock_session_mgr

        cli._init_session_manager()
        cli._handle_command("start fake-session")

        captured = capsys.readouterr()
        assert "Session not found" in captured.out


class TestCLIWithOrchestrator:
    """Tests for CLI with running orchestrator."""

    @pytest.fixture
    def cli_with_orchestrator(self):
        """Create CLI with mock orchestrator."""
        config = CLIConfig(use_colors=False)
        cli = CLI(config)

        mock_orchestrator = MagicMock()
        mock_orchestrator.is_running = True
        mock_orchestrator.current_phase = MagicMock()
        mock_orchestrator.current_phase.value = "recon"
        mock_orchestrator.router = MagicMock()
        mock_orchestrator.router.get_current_agent.return_value = "recon_agent"
        mock_orchestrator.router.can_advance.return_value = True
        mock_orchestrator.get_status.return_value = {
            "session_id": "test",
            "scope_tag": "test",
            "current_phase": "recon",
            "is_running": True,
            "state_version": 1,
            "pending_approvals": 0,
            "audit_events_count": 5,
        }

        cli._orchestrator = mock_orchestrator
        cli._session_id = "test-session"
        cli._session_manager = MagicMock()

        return cli

    def test_status_with_session(self, cli_with_orchestrator, capsys):
        """Test status command with session."""
        cli_with_orchestrator._handle_command("status")

        captured = capsys.readouterr()
        assert "Session ID" in captured.out or "test" in captured.out

    def test_phase_with_session(self, cli_with_orchestrator, capsys):
        """Test phase command with session."""
        cli_with_orchestrator._handle_command("phase")

        captured = capsys.readouterr()
        assert "recon" in captured.out

    def test_advance_with_session(self, cli_with_orchestrator, capsys):
        """Test advance command with session."""
        mock_transition = MagicMock()
        mock_transition.from_phase = MagicMock()
        mock_transition.from_phase.value = "recon"
        mock_transition.to_phase = MagicMock()
        mock_transition.to_phase.value = "enumeration"

        cli_with_orchestrator._orchestrator.advance_phase.return_value = mock_transition

        cli_with_orchestrator._handle_command("advance")

        captured = capsys.readouterr()
        assert "Advanced" in captured.out

    def test_advance_cannot_advance(self, cli_with_orchestrator, capsys):
        """Test advance when cannot advance."""
        cli_with_orchestrator._orchestrator.advance_phase.return_value = None

        cli_with_orchestrator._handle_command("advance")

        captured = capsys.readouterr()
        assert "Cannot advance" in captured.out

    def test_stop_with_session(self, cli_with_orchestrator, capsys):
        """Test stop command with session."""
        cli_with_orchestrator._handle_command("stop")

        captured = capsys.readouterr()
        assert "stopped" in captured.out.lower()
        cli_with_orchestrator._orchestrator.stop.assert_called()

    def test_stop_with_reason(self, cli_with_orchestrator):
        """Test stop command with reason."""
        cli_with_orchestrator._handle_command("stop Test reason here")

        cli_with_orchestrator._orchestrator.stop.assert_called_with(
            "Test reason here", "user"
        )

    def test_run_no_handler(self, cli_with_orchestrator, capsys):
        """Test run without agent handler."""
        cli_with_orchestrator._orchestrator._agent_handlers = {}

        cli_with_orchestrator._handle_command("run")

        captured = capsys.readouterr()
        assert "No handler" in captured.out

    def test_run_with_handler(self, cli_with_orchestrator, capsys):
        """Test run with agent handler."""
        cli_with_orchestrator._orchestrator._agent_handlers = {"recon_agent": MagicMock()}

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.duration_ms = 1500
        cli_with_orchestrator._orchestrator.run_phase.return_value = mock_result

        cli_with_orchestrator._handle_command("run")

        captured = capsys.readouterr()
        assert "completed successfully" in captured.out

    def test_run_failure(self, cli_with_orchestrator, capsys):
        """Test run with failure."""
        cli_with_orchestrator._orchestrator._agent_handlers = {"recon_agent": MagicMock()}

        mock_result = MagicMock()
        mock_result.success = False
        mock_result.error = "Connection failed"
        cli_with_orchestrator._orchestrator.run_phase.return_value = mock_result

        cli_with_orchestrator._handle_command("run")

        captured = capsys.readouterr()
        assert "failed" in captured.out


class TestCLIScopeAndFindings:
    """Tests for CLI scope and findings commands."""

    @pytest.fixture
    def cli_with_session(self):
        """Create CLI with mock session."""
        config = CLIConfig(use_colors=False)
        cli = CLI(config)

        cli._session_id = "test-session"
        cli._session_manager = MagicMock()
        cli._orchestrator = MagicMock()
        cli._orchestrator.is_running = True

        return cli

    def test_scope_display(self, cli_with_session, capsys):
        """Test scope display."""
        mock_state_store = MagicMock()
        mock_state_store.read_json.return_value = {
            "targets": [
                {"value": "192.168.1.1", "type": "ip"},
                {"value": "example.com", "type": "domain"},
            ],
            "allowed_operations": ["port_scan", "web_crawl"],
        }
        cli_with_session._session_manager.get_state_store.return_value = mock_state_store

        cli_with_session._handle_command("scope")

        captured = capsys.readouterr()
        assert "Current Scope" in captured.out
        assert "192.168.1.1" in captured.out
        assert "example.com" in captured.out

    def test_scope_not_found(self, cli_with_session, capsys):
        """Test scope when not defined."""
        mock_state_store = MagicMock()
        mock_state_store.read_json.side_effect = FileNotFoundError()
        cli_with_session._session_manager.get_state_store.return_value = mock_state_store

        cli_with_session._handle_command("scope")

        captured = capsys.readouterr()
        assert "No scope defined" in captured.out

    def test_findings_display(self, cli_with_session, capsys):
        """Test findings display."""
        mock_state_store = MagicMock()
        mock_state_store.read_jsonl.return_value = [
            {
                "title": "SQL Injection",
                "severity": "high",
                "affected_component": "login.php",
            },
            {
                "title": "XSS",
                "severity": "medium",
                "affected_component": "search.php",
            },
        ]
        cli_with_session._session_manager.get_state_store.return_value = mock_state_store

        cli_with_session._handle_command("findings")

        captured = capsys.readouterr()
        assert "Findings (2)" in captured.out
        assert "SQL Injection" in captured.out
        assert "XSS" in captured.out

    def test_findings_empty(self, cli_with_session, capsys):
        """Test findings when empty."""
        mock_state_store = MagicMock()
        mock_state_store.read_jsonl.return_value = []
        cli_with_session._session_manager.get_state_store.return_value = mock_state_store

        cli_with_session._handle_command("findings")

        captured = capsys.readouterr()
        assert "No findings" in captured.out


class TestCLIApproval:
    """Tests for CLI approval handling."""

    @pytest.fixture
    def cli(self):
        """Create CLI instance."""
        config = CLIConfig(use_colors=False)
        return CLI(config)

    def test_approval_callback_approved(self, cli):
        """Test approval callback when approved."""
        cli.prompts.approval_prompt = MagicMock(return_value=True)

        from src.orchestrator.approval_gate import ApprovalRequest
        from datetime import datetime

        request = ApprovalRequest(
            request_id="req-001",
            operation="metasploit_execute",
            target="192.168.1.1",
            created_at=datetime.utcnow(),
            risk_level="high",
        )

        result = cli._approval_callback(request)

        assert result.approved is True
        assert result.responded_by == "cli_user"

    def test_approval_callback_denied(self, cli):
        """Test approval callback when denied."""
        cli.prompts.approval_prompt = MagicMock(return_value=False)

        from src.orchestrator.approval_gate import ApprovalRequest
        from datetime import datetime

        request = ApprovalRequest(
            request_id="req-001",
            operation="brute_force",
            target="10.0.0.1",
            created_at=datetime.utcnow(),
            risk_level="critical",
        )

        result = cli._approval_callback(request)

        assert result.approved is False
        assert "denied" in result.reason.lower()


class TestCLICleanup:
    """Tests for CLI cleanup."""

    def test_cleanup_with_running_orchestrator(self, capsys):
        """Test cleanup stops running orchestrator."""
        config = CLIConfig(use_colors=False)
        cli = CLI(config)

        mock_orchestrator = MagicMock()
        mock_orchestrator.is_running = True
        cli._orchestrator = mock_orchestrator

        cli._cleanup()

        mock_orchestrator.stop.assert_called_with("CLI exit", "cli")
        captured = capsys.readouterr()
        assert "Goodbye" in captured.out

    def test_cleanup_without_orchestrator(self, capsys):
        """Test cleanup without orchestrator."""
        config = CLIConfig(use_colors=False)
        cli = CLI(config)

        cli._cleanup()

        captured = capsys.readouterr()
        assert "Goodbye" in captured.out


class TestCLIExitHandling:
    """Tests for CLI exit handling."""

    def test_exit_with_running_session_confirmed(self):
        """Test exit with running session, confirmed stop."""
        config = CLIConfig(use_colors=False)
        cli = CLI(config)

        mock_orchestrator = MagicMock()
        mock_orchestrator.is_running = True
        cli._orchestrator = mock_orchestrator
        cli.prompts.confirm = MagicMock(return_value=True)

        result = cli._cmd_exit([])

        mock_orchestrator.stop.assert_called()
        assert result == "exit"

    def test_exit_with_running_session_cancelled(self):
        """Test exit with running session, cancel."""
        config = CLIConfig(use_colors=False)
        cli = CLI(config)

        mock_orchestrator = MagicMock()
        mock_orchestrator.is_running = True
        cli._orchestrator = mock_orchestrator
        cli.prompts.confirm = MagicMock(return_value=False)

        result = cli._cmd_exit([])

        mock_orchestrator.stop.assert_not_called()
        assert result == "exit"
