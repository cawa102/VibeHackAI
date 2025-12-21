"""
Kali Linux Passer - Normalizes Kali tool output into common schema objects.

Handles generic command execution results from Kali Linux tools.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union

from .base import BasePasser, MCPType, PasserRegistry, PasserResult
from ..schemas import ExecutionResult, Observation
from ..schemas.execution_result import ExecutionStatus, ErrorClass


@PasserRegistry.register
class KaliPasser(BasePasser):
    """
    Passer for Kali Linux tool output.

    Converts command execution results to ExecutionResult objects.
    """

    mcp_type = MCPType.KALI
    tool_name = "kali"

    # Common Kali tools and their success indicators
    TOOL_PATTERNS = {
        "nikto": {
            "success": [r"\d+ item\(s\) reported", r"host\(s\) tested"],
            "failure": [r"error", r"cannot connect"],
        },
        "gobuster": {
            "success": [r"found:", r"status: 200", r"finished"],
            "failure": [r"error", r"unable to connect"],
        },
        "dirb": {
            "success": [r"FOUND:", r"DIRECTORY:", r"URL_BASE"],
            "failure": [r"error", r"not found"],
        },
        "sqlmap": {
            "success": [r"sqlmap identified", r"injectable", r"database:"],
            "failure": [r"not injectable", r"connection timed out"],
        },
        "hydra": {
            "success": [r"\[.+\] host:", r"valid password found", r"login:"],
            "failure": [r"0 valid passwords found", r"error"],
        },
        "wpscan": {
            "success": [r"vulnerabilities identified", r"interesting finding"],
            "failure": [r"scan aborted", r"error"],
        },
        "enum4linux": {
            "success": [r"users:", r"shares:", r"groups:"],
            "failure": [r"failed to", r"error"],
        },
        "ffuf": {
            "success": [r"status: 200", r"found:", r"results"],
            "failure": [r"error", r"no results"],
        },
        "default": {
            "success": [r"success", r"completed", r"finished"],
            "failure": [r"error", r"failed", r"unable to"],
        },
    }

    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """Check if this is Kali tool output."""
        data = self._parse_input(raw_output)

        if data is not None:
            # JSON format with Kali indicators
            kali_indicators = [
                "command", "tool", "stdout", "stderr", "exit_code",
                "kali", "output", "cmd"
            ]
            return any(key in data for key in kali_indicators)

        # Check raw output for Kali tool signatures
        if isinstance(raw_output, (str, bytes)):
            text = raw_output if isinstance(raw_output, str) else raw_output.decode("utf-8", errors="ignore")
            tool_names = list(self.TOOL_PATTERNS.keys())
            tool_names.remove("default")
            return any(tool in text.lower() for tool in tool_names)

        return False

    def normalize(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize Kali tool output.

        Args:
            raw_output: Tool output (string, bytes, or JSON).
            **kwargs: Additional parameters (plan_id, step_index, tool_name).

        Returns:
            PasserResult with ExecutionResult objects.
        """
        result = self._create_result()

        plan_id = kwargs.get("plan_id", "kali-plan")
        step_index = kwargs.get("step_index", 0)
        tool_name = kwargs.get("tool_name")

        data = self._parse_input(raw_output)
        if data is not None:
            return self._normalize_json(data, plan_id, step_index, tool_name, result)

        # Raw command output
        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, str):
            return self._normalize_raw(raw_output, plan_id, step_index, tool_name, result)

        result.add_error("Unsupported Kali output format")
        return result

    def _parse_input(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Parse input into dictionary."""
        if isinstance(raw_output, dict):
            return raw_output

        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, str):
            try:
                return json.loads(raw_output)
            except json.JSONDecodeError:
                return None

        return None

    def _normalize_json(
        self,
        data: Dict[str, Any],
        plan_id: str,
        step_index: int,
        tool_name: Optional[str],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize JSON format output."""
        result.raw_data = data

        # Get tool name
        if not tool_name:
            tool_name = data.get("tool") or data.get("command", "").split()[0] or "unknown"

        # Get output
        stdout = data.get("stdout", "") or data.get("output", "")
        stderr = data.get("stderr", "")
        exit_code = self._safe_int(data.get("exit_code"), result=result)

        # Determine status
        status, error_class = self._determine_status(
            stdout + stderr, tool_name, exit_code
        )

        # Build summary
        summary = self._build_summary(tool_name, status, stdout)

        try:
            # Error class is set for failure and timeout statuses
            set_error_class = status in (ExecutionStatus.FAILURE, ExecutionStatus.TIMEOUT)

            exec_result = ExecutionResult(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                plan_id=plan_id,
                step_index=step_index,
                status=status,
                output_summary=summary,
                command_executed=data.get("command") or data.get("cmd"),
                parameters_used=data.get("parameters", {}),
                exit_code=exit_code,
                error_class=error_class if set_error_class else None,
                error_message=stderr[:500] if stderr and set_error_class else None,
                metadata={
                    "tool": tool_name,
                    "stdout_length": len(stdout),
                    "stderr_length": len(stderr),
                    "duration_seconds": data.get("duration"),
                },
            )
            result.execution_results.append(exec_result)
        except Exception as e:
            result.add_error(f"Failed to create ExecutionResult: {e}")

        # Create observation
        observation = self._create_observation(
            tool_name, stdout, status, result
        )
        if observation:
            result.observations.append(observation)

        return result

    def _normalize_raw(
        self,
        output: str,
        plan_id: str,
        step_index: int,
        tool_name: Optional[str],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize raw command output."""
        # Detect tool from output if not provided
        if not tool_name:
            tool_name = self._detect_tool(output)

        # Determine status
        status, error_class = self._determine_status(output, tool_name, None)

        # Build summary
        summary = self._build_summary(tool_name, status, output)

        try:
            exec_result = ExecutionResult(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                plan_id=plan_id,
                step_index=step_index,
                status=status,
                output_summary=summary,
                command_executed=tool_name,
                error_class=error_class if status == ExecutionStatus.FAILURE else None,
                metadata={
                    "tool": tool_name,
                    "output_length": len(output),
                },
            )
            result.execution_results.append(exec_result)
        except Exception as e:
            result.add_error(f"Failed to create ExecutionResult: {e}")

        # Create observation
        observation = self._create_observation(
            tool_name, output, status, result
        )
        if observation:
            result.observations.append(observation)

        return result

    def _detect_tool(self, output: str) -> str:
        """Detect which Kali tool produced the output."""
        output_lower = output.lower()

        tool_signatures = {
            "nikto": ["nikto", "- nikto v"],
            "gobuster": ["gobuster", "dir/vhost/dns/fuzz"],
            "dirb": ["dirb", "url_base"],
            "sqlmap": ["sqlmap", "[info]", "[warning]", "parameter:"],
            "hydra": ["hydra", "[data]", "password attack"],
            "wpscan": ["wpscan", "wordpress security scanner"],
            "enum4linux": ["enum4linux", "session setup"],
            "ffuf": ["ffuf", ":: progress"],
            "nmap": ["nmap", "scan report"],
            "masscan": ["masscan", "banner:"],
            "nuclei": ["nuclei", "[info]", "[critical]"],
            "whatweb": ["whatweb", "http-title"],
            "sublist3r": ["sublist3r", "enumerating subdomains"],
            "amass": ["amass", "owasp amass"],
            "theHarvester": ["theharvester", "searching"],
        }

        for tool, signatures in tool_signatures.items():
            if any(sig in output_lower for sig in signatures):
                return tool

        return "unknown"

    def _determine_status(
        self,
        output: str,
        tool_name: str,
        exit_code: Optional[int],
    ) -> tuple[ExecutionStatus, Optional[ErrorClass]]:
        """Determine execution status and error class."""
        # Check exit code first
        if exit_code is not None:
            if exit_code == 0:
                return ExecutionStatus.SUCCESS, None
            elif exit_code == 124:  # timeout exit code
                return ExecutionStatus.TIMEOUT, ErrorClass.TIMEOUT

        # Check for timeout in output
        output_lower = output.lower()
        if "timeout" in output_lower or exit_code == 124:
            return ExecutionStatus.TIMEOUT, ErrorClass.TIMEOUT

        # Non-zero exit code means failure
        if exit_code is not None and exit_code != 0:
            error_class = self._classify_error(output_lower) if output else ErrorClass.TOOL_ERROR
            return ExecutionStatus.FAILURE, error_class

        output_lower = output.lower()

        # Get patterns for the tool
        patterns = self.TOOL_PATTERNS.get(tool_name, self.TOOL_PATTERNS["default"])

        # Check for success patterns
        for pattern in patterns["success"]:
            if re.search(pattern, output_lower):
                return ExecutionStatus.SUCCESS, None

        # Check for failure patterns
        for pattern in patterns["failure"]:
            if re.search(pattern, output_lower):
                error_class = self._classify_error(output_lower)
                return ExecutionStatus.FAILURE, error_class

        # Default to partial/unknown
        return ExecutionStatus.PARTIAL, None

    def _classify_error(self, output: str) -> ErrorClass:
        """Classify the type of error."""
        if any(x in output for x in ["connection refused", "connection timed out", "network unreachable"]):
            return ErrorClass.NETWORK
        if any(x in output for x in ["permission denied", "access denied", "unauthorized"]):
            return ErrorClass.PERMISSION
        if any(x in output for x in ["not found", "does not exist", "no such"]):
            return ErrorClass.NOT_FOUND
        if any(x in output for x in ["timeout", "timed out"]):
            return ErrorClass.TIMEOUT
        if any(x in output for x in ["parse error", "invalid format", "syntax error"]):
            return ErrorClass.PARSE

        return ErrorClass.TOOL_ERROR

    def _build_summary(
        self,
        tool_name: str,
        status: ExecutionStatus,
        output: str,
    ) -> str:
        """Build execution summary."""
        # Try to extract key findings
        findings = self._extract_findings(tool_name, output)

        if findings:
            return f"{tool_name}: {findings}"

        return f"{tool_name} execution: {status.value}"

    def _extract_findings(self, tool_name: str, output: str) -> Optional[str]:
        """Extract key findings from tool output."""
        output_lower = output.lower()

        if tool_name == "gobuster" or tool_name == "dirb" or tool_name == "ffuf":
            # Count discovered paths
            found_count = len(re.findall(r"status: 200|found:", output_lower))
            if found_count:
                return f"{found_count} paths discovered"

        elif tool_name == "nikto":
            # Count vulnerabilities
            items = re.search(r"(\d+) item\(s\) reported", output_lower)
            if items:
                return f"{items.group(1)} items reported"

        elif tool_name == "sqlmap":
            if "injectable" in output_lower:
                return "SQL injection point found"
            if "database:" in output_lower:
                return "Database enumerated"

        elif tool_name == "hydra":
            passwords = re.findall(r"login:\s*\S+\s*password:\s*\S+", output_lower)
            if passwords:
                return f"{len(passwords)} credentials found"

        elif tool_name == "wpscan":
            vulns = len(re.findall(r"vulnerability", output_lower))
            if vulns:
                return f"{vulns} vulnerabilities identified"

        return None

    def _create_observation(
        self,
        tool_name: str,
        output: str,
        status: ExecutionStatus,
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create observation for the tool execution."""
        try:
            summary = self._build_summary(tool_name, status, output)

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=tool_name,
                action="tool_execution",
                summary=summary,
                raw_output_preview=output[:500] if output else None,
                success=status == ExecutionStatus.SUCCESS,
                metadata={
                    "status": status.value,
                    "output_length": len(output),
                    "execution_result_ids": [er.id for er in result.execution_results],
                },
            )
            return observation
        except Exception as e:
            result.add_warning(f"Failed to create observation: {e}")
            return None
