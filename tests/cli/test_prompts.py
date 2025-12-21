"""Tests for CLI prompts."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from src.cli.prompts import Prompts


class TestPromptsText:
    """Tests for text prompts."""

    def test_text_with_value(self):
        """Test text prompt with user value."""
        mock_input = MagicMock(return_value="test value")
        prompts = Prompts(input_func=mock_input)

        result = prompts.text("Enter name")

        assert result == "test value"

    def test_text_with_default(self):
        """Test text prompt using default."""
        mock_input = MagicMock(return_value="")
        prompts = Prompts(input_func=mock_input)

        result = prompts.text("Enter name", default="default_name")

        assert result == "default_name"

    def test_text_required_empty(self):
        """Test required text prompt with empty input."""
        # First empty, then value
        mock_input = MagicMock(side_effect=["", "valid"])
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.text("Enter name", required=True)

        assert result == "valid"
        mock_print.assert_called()  # Should print required message

    def test_text_optional_empty(self):
        """Test optional text prompt with empty input."""
        mock_input = MagicMock(return_value="")
        prompts = Prompts(input_func=mock_input)

        result = prompts.text("Enter name", required=False)

        assert result is None

    def test_text_keyboard_interrupt(self):
        """Test text prompt with keyboard interrupt."""
        mock_input = MagicMock(side_effect=KeyboardInterrupt())
        prompts = Prompts(input_func=mock_input)

        result = prompts.text("Enter name")

        assert result is None


class TestPromptsConfirm:
    """Tests for confirm prompts."""

    def test_confirm_yes(self):
        """Test confirm with yes."""
        for yes_val in ["y", "yes", "Y", "YES", "Yes"]:
            mock_input = MagicMock(return_value=yes_val)
            prompts = Prompts(input_func=mock_input)

            result = prompts.confirm("Continue?")

            assert result is True

    def test_confirm_no(self):
        """Test confirm with no."""
        for no_val in ["n", "no", "N", "NO", "anything"]:
            mock_input = MagicMock(return_value=no_val)
            prompts = Prompts(input_func=mock_input)

            result = prompts.confirm("Continue?")

            assert result is False

    def test_confirm_default_true(self):
        """Test confirm with default true."""
        mock_input = MagicMock(return_value="")
        prompts = Prompts(input_func=mock_input)

        result = prompts.confirm("Continue?", default=True)

        assert result is True

    def test_confirm_default_false(self):
        """Test confirm with default false."""
        mock_input = MagicMock(return_value="")
        prompts = Prompts(input_func=mock_input)

        result = prompts.confirm("Continue?", default=False)

        assert result is False


class TestPromptsChoice:
    """Tests for choice prompts."""

    def test_choice_by_number(self):
        """Test choice selection by number."""
        mock_input = MagicMock(return_value="2")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.choice("Select:", ["apple", "banana", "cherry"])

        assert result == "banana"

    def test_choice_by_name(self):
        """Test choice selection by name."""
        mock_input = MagicMock(return_value="ban")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.choice("Select:", ["apple", "banana", "cherry"])

        assert result == "banana"

    def test_choice_default(self):
        """Test choice with default."""
        mock_input = MagicMock(return_value="")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.choice("Select:", ["apple", "banana", "cherry"], default=1)

        assert result == "apple"

    def test_choice_invalid_number(self):
        """Test choice with invalid number then valid."""
        mock_input = MagicMock(side_effect=["99", "1"])
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.choice("Select:", ["apple", "banana"])

        assert result == "apple"

    def test_choice_keyboard_interrupt(self):
        """Test choice with keyboard interrupt."""
        mock_input = MagicMock(side_effect=KeyboardInterrupt())
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.choice("Select:", ["apple", "banana"])

        assert result is None


class TestPromptsMultiChoice:
    """Tests for multi-choice prompts."""

    def test_multi_choice_single(self):
        """Test multi-choice with single selection."""
        mock_input = MagicMock(return_value="2")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.multi_choice("Select:", ["a", "b", "c"])

        assert result == ["b"]

    def test_multi_choice_multiple(self):
        """Test multi-choice with multiple selections."""
        mock_input = MagicMock(return_value="1, 3")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.multi_choice("Select:", ["a", "b", "c"])

        assert result == ["a", "c"]

    def test_multi_choice_all(self):
        """Test multi-choice select all."""
        mock_input = MagicMock(return_value="a")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.multi_choice("Select:", ["a", "b", "c"])

        assert result == ["a", "b", "c"]

    def test_multi_choice_defaults(self):
        """Test multi-choice with defaults."""
        mock_input = MagicMock(return_value="")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.multi_choice("Select:", ["a", "b", "c"], defaults=[1, 2])

        assert result == ["a", "b"]

    def test_multi_choice_keyboard_interrupt(self):
        """Test multi-choice with interrupt."""
        mock_input = MagicMock(side_effect=KeyboardInterrupt())
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.multi_choice("Select:", ["a", "b"])

        assert result == []


class TestPromptsInteger:
    """Tests for integer prompts."""

    def test_integer_valid(self):
        """Test integer with valid value."""
        mock_input = MagicMock(return_value="42")
        prompts = Prompts(input_func=mock_input)

        result = prompts.integer("Enter number")

        assert result == 42

    def test_integer_default(self):
        """Test integer with default."""
        mock_input = MagicMock(return_value="")
        prompts = Prompts(input_func=mock_input)

        result = prompts.integer("Enter number", default=10)

        assert result == 10

    def test_integer_range(self):
        """Test integer with range validation."""
        mock_input = MagicMock(side_effect=["0", "200", "50"])
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.integer("Enter number", min_val=1, max_val=100)

        assert result == 50

    def test_integer_invalid(self):
        """Test integer with invalid then valid."""
        mock_input = MagicMock(side_effect=["abc", "42"])
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.integer("Enter number")

        assert result == 42


class TestPromptsPassword:
    """Tests for password prompts."""

    def test_password(self):
        """Test password prompt."""
        prompts = Prompts()

        # This would normally use getpass, but we can test the fallback
        with pytest.raises(Exception):
            # getpass fails in test environment usually
            pass


class TestPromptsScopeInput:
    """Tests for scope input."""

    def test_scope_input_basic(self):
        """Test basic scope input."""
        inputs = iter([
            "192.168.1.1",  # First target
            "",             # Done with targets
            "1,2,3",        # Operations
        ])
        mock_input = MagicMock(side_effect=lambda x: next(inputs))
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.scope_input()

        assert "targets" in result
        assert len(result["targets"]) == 1
        assert result["targets"][0]["value"] == "192.168.1.1"
        assert result["targets"][0]["type"] == "ip"

    def test_scope_input_cidr(self):
        """Test scope input with CIDR."""
        inputs = iter([
            "192.168.1.0/24",
            "",
            "1",
        ])
        mock_input = MagicMock(side_effect=lambda x: next(inputs))
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.scope_input()

        assert result["targets"][0]["type"] == "cidr"

    def test_scope_input_url(self):
        """Test scope input with URL."""
        inputs = iter([
            "https://example.com",
            "",
            "1",
        ])
        mock_input = MagicMock(side_effect=lambda x: next(inputs))
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.scope_input()

        assert result["targets"][0]["type"] == "url"

    def test_scope_input_domain(self):
        """Test scope input with domain."""
        inputs = iter([
            "example.com",
            "",
            "1",
        ])
        mock_input = MagicMock(side_effect=lambda x: next(inputs))
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.scope_input()

        assert result["targets"][0]["type"] == "domain"

    def test_scope_input_no_targets(self):
        """Test scope input with no targets."""
        inputs = iter([
            "",  # No targets
            "1",  # Operations still asked
        ])
        mock_input = MagicMock(side_effect=lambda x: next(inputs))
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.scope_input()

        assert result["targets"] == []


class TestPromptsApproval:
    """Tests for approval prompts."""

    def test_approval_approved(self):
        """Test approval prompt approved."""
        mock_input = MagicMock(return_value="y")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.approval_prompt(
            operation="metasploit_execute",
            target="192.168.1.1",
            risk_level="high",
        )

        assert result is True
        # Should print approval request info
        assert mock_print.call_count >= 4

    def test_approval_denied(self):
        """Test approval prompt denied."""
        mock_input = MagicMock(return_value="n")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.approval_prompt(
            operation="brute_force",
            target="10.0.0.1",
            risk_level="critical",
        )

        assert result is False

    def test_approval_with_details(self):
        """Test approval prompt with details."""
        mock_input = MagicMock(return_value="y")
        mock_print = MagicMock()
        prompts = Prompts(input_func=mock_input, print_func=mock_print)

        result = prompts.approval_prompt(
            operation="exploit_execute",
            target="192.168.1.1",
            risk_level="high",
            details={
                "CVE": "CVE-2024-1234",
                "Payload": "reverse_shell",
            },
        )

        assert result is True
        # Should print details
        printed = [str(call) for call in mock_print.call_args_list]
        assert any("CVE" in p for p in printed)
