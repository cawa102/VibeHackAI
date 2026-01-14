"""
Prompts for CLI user interaction.

Provides input prompts and validation for user input.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional


class Prompts:
    """User input prompts for CLI."""

    def __init__(
        self,
        input_func: Optional[Callable[[str], str]] = None,
        print_func: Optional[Callable[[str], None]] = None,
    ):
        """
        Initialize prompts.

        Args:
            input_func: Function for getting input (default: input()).
            print_func: Function for printing (default: print()).
        """
        self._input = input_func or input
        self._print = print_func or print

    def text(
        self,
        prompt: str,
        default: Optional[str] = None,
        required: bool = True,
    ) -> Optional[str]:
        """
        Prompt for text input.

        Args:
            prompt: Prompt message.
            default: Default value.
            required: Whether input is required.

        Returns:
            User input or default.
        """
        default_str = f" [{default}]" if default else ""
        full_prompt = f"{prompt}{default_str}: "

        while True:
            try:
                value = self._input(full_prompt).strip()

                if not value:
                    if default:
                        return default
                    if not required:
                        return None
                    self._print("This field is required.")
                    continue

                return value

            except (KeyboardInterrupt, EOFError):
                return None

    def confirm(
        self,
        prompt: str,
        default: bool = False,
    ) -> bool:
        """
        Prompt for yes/no confirmation.

        Args:
            prompt: Prompt message.
            default: Default value.

        Returns:
            True for yes, False for no.
        """
        default_str = "Y/n" if default else "y/N"
        full_prompt = f"{prompt} [{default_str}]: "

        try:
            value = self._input(full_prompt).strip().lower()

            if not value:
                return default

            return value in ("y", "yes", "true", "1")

        except (KeyboardInterrupt, EOFError):
            return False

    def choice(
        self,
        prompt: str,
        choices: List[str],
        default: Optional[int] = None,
    ) -> Optional[str]:
        """
        Prompt for choice from list.

        Args:
            prompt: Prompt message.
            choices: List of choices.
            default: Default index (1-based).

        Returns:
            Selected choice or None.
        """
        self._print(f"\n{prompt}")
        for i, choice in enumerate(choices, 1):
            marker = "*" if default == i else " "
            self._print(f"  {marker}{i}. {choice}")

        default_str = f" [{default}]" if default else ""
        full_prompt = f"\nSelect{default_str}: "

        while True:
            try:
                value = self._input(full_prompt).strip()

                if not value and default:
                    return choices[default - 1]

                try:
                    idx = int(value)
                    if 1 <= idx <= len(choices):
                        return choices[idx - 1]
                    self._print(f"Please enter a number between 1 and {len(choices)}")
                except ValueError:
                    # Try matching by name
                    for choice in choices:
                        if choice.lower().startswith(value.lower()):
                            return choice
                    self._print("Invalid selection.")

            except (KeyboardInterrupt, EOFError):
                return None

    def multi_choice(
        self,
        prompt: str,
        choices: List[str],
        defaults: Optional[List[int]] = None,
    ) -> List[str]:
        """
        Prompt for multiple choices from list.

        Args:
            prompt: Prompt message.
            choices: List of choices.
            defaults: Default indices (1-based).

        Returns:
            List of selected choices.
        """
        defaults = defaults or []
        selected = set(defaults)

        self._print(f"\n{prompt}")
        self._print("(Enter numbers separated by commas, or 'a' for all)")

        for i, choice in enumerate(choices, 1):
            marker = "*" if i in selected else " "
            self._print(f"  {marker}{i}. {choice}")

        full_prompt = "\nSelect: "

        try:
            value = self._input(full_prompt).strip()

            if not value:
                return [choices[i - 1] for i in defaults]

            if value.lower() == "a":
                return choices.copy()

            selected_choices = []
            for part in value.split(","):
                part = part.strip()
                try:
                    idx = int(part)
                    if 1 <= idx <= len(choices):
                        selected_choices.append(choices[idx - 1])
                except ValueError:
                    pass

            return selected_choices

        except (KeyboardInterrupt, EOFError):
            return []

    def integer(
        self,
        prompt: str,
        default: Optional[int] = None,
        min_val: Optional[int] = None,
        max_val: Optional[int] = None,
    ) -> Optional[int]:
        """
        Prompt for integer input.

        Args:
            prompt: Prompt message.
            default: Default value.
            min_val: Minimum value.
            max_val: Maximum value.

        Returns:
            Integer value or None.
        """
        default_str = f" [{default}]" if default is not None else ""
        range_str = ""
        if min_val is not None and max_val is not None:
            range_str = f" ({min_val}-{max_val})"
        full_prompt = f"{prompt}{range_str}{default_str}: "

        while True:
            try:
                value = self._input(full_prompt).strip()

                if not value:
                    return default

                try:
                    int_val = int(value)

                    if min_val is not None and int_val < min_val:
                        self._print(f"Value must be at least {min_val}")
                        continue

                    if max_val is not None and int_val > max_val:
                        self._print(f"Value must be at most {max_val}")
                        continue

                    return int_val

                except ValueError:
                    self._print("Please enter a valid number.")

            except (KeyboardInterrupt, EOFError):
                return None

    def password(self, prompt: str) -> Optional[str]:
        """
        Prompt for password (hidden input).

        Args:
            prompt: Prompt message.

        Returns:
            Password string or None.
        """
        try:
            import getpass
            return getpass.getpass(f"{prompt}: ")
        except (KeyboardInterrupt, EOFError):
            return None
        except Exception:
            # Fallback to regular input if getpass fails
            return self.text(prompt)

    def scope_input(self) -> Dict[str, Any]:
        """
        Prompt for scope definition.

        Returns:
            Scope configuration dictionary.
        """
        self._print("\n=== Scope Definition ===\n")

        targets = []
        self._print("Enter targets (IP, CIDR, domain, URL). Empty line to finish.")
        while True:
            target = self.text("Target", required=False)
            if not target:
                break

            # Detect type
            target_type = "ip"
            if "/" in target:
                target_type = "cidr"
            elif target.startswith("http"):
                target_type = "url"
            elif "." in target and not target[0].isdigit():
                target_type = "domain"

            targets.append({"value": target, "type": target_type})

        if not targets:
            self._print("Warning: No targets defined.")

        # Allowed operations
        operations = [
            "passive_recon",
            "active_recon",
            "port_scan",
            "web_crawl",
            "directory_enum",
            "service_enum",
            "vuln_scan",
            "cve_lookup",
            "exploit_verify",
            "exploit_execute",
        ]

        selected_ops = self.multi_choice(
            "Select allowed operations:",
            operations,
            defaults=[1, 2, 3, 4, 5, 6, 7, 8],  # Default safe operations
        )

        return {
            "targets": targets,
            "allowed_operations": selected_ops,
        }

    def approval_prompt(
        self,
        operation: str,
        target: str,
        risk_level: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Prompt for operation approval.

        Args:
            operation: Operation to approve.
            target: Target of operation.
            risk_level: Risk level.
            details: Additional details.

        Returns:
            True if approved, False if denied.
        """
        self._print("\n" + "=" * 50)
        self._print("APPROVAL REQUIRED")
        self._print("=" * 50)
        self._print(f"\nOperation: {operation}")
        self._print(f"Target: {target}")
        self._print(f"Risk Level: {risk_level.upper()}")

        if details:
            self._print("\nDetails:")
            for key, value in details.items():
                self._print(f"  {key}: {value}")

        self._print("")

        return self.confirm("Do you approve this operation?", default=False)
