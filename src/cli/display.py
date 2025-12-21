"""
Display utilities for CLI.

Provides formatted output for the command-line interface.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


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
