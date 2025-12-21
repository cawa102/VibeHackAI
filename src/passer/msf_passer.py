"""
Metasploit Passer - Normalizes Metasploit Framework output into common schema objects.

Handles module execution results, sessions, and converts to ExecutionResult objects.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union

from .base import BasePasser, MCPType, PasserRegistry, PasserResult
from ..schemas import ExecutionResult, Observation
from ..schemas.execution_result import ExecutionStatus, ErrorClass


@PasserRegistry.register
class MetasploitPasser(BasePasser):
    """
    Passer for Metasploit Framework output.

    Converts module execution results and session info to ExecutionResult objects.
    """

    mcp_type = MCPType.METASPLOIT
    tool_name = "metasploit"

    # Patterns indicating success
    SUCCESS_PATTERNS = [
        r"session \d+ opened",
        r"meterpreter session \d+ opened",
        r"command shell session \d+ opened",
        r"exploit completed",
        r"auxiliary module execution completed",
        r"post module execution completed",
        r"\[\+\]",  # Metasploit success indicator
    ]

    # Patterns indicating failure
    FAILURE_PATTERNS = [
        r"exploit failed",
        r"no session was created",
        r"execution failed",
        r"module execution failed",
        r"\[-\]",  # Metasploit failure indicator
        r"error",
    ]

    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """Check if this is Metasploit output."""
        data = self._parse_input(raw_output)
        if data is None:
            # Check if it's raw MSF console output
            if isinstance(raw_output, (str, bytes)):
                text = raw_output if isinstance(raw_output, str) else raw_output.decode("utf-8", errors="ignore")
                text_lower = text.lower()
                # More specific MSF patterns
                msf_patterns = [
                    "msf6", "msf5", "msf>", "metasploit",
                    "meterpreter", "exploit(", "auxiliary(",
                    "meterpreter session", "command shell session",
                    "[*] starting", "[+] meterpreter",
                ]
                return any(pattern in text_lower for pattern in msf_patterns)
            return False

        # Check for MSF-specific JSON fields
        msf_indicators = [
            "module", "sessions", "job_id", "uuid",
            "exploit", "payload", "lhost", "rhost",
            "module_type", "module_name"
        ]
        return any(key in data for key in msf_indicators)

    def normalize(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize Metasploit output.

        Args:
            raw_output: Metasploit console output or JSON response.
            **kwargs: Additional parameters (plan_id, step_index).

        Returns:
            PasserResult with ExecutionResult objects.
        """
        result = self._create_result()

        plan_id = kwargs.get("plan_id", "msf-plan")
        step_index = kwargs.get("step_index", 0)

        data = self._parse_input(raw_output)
        if data is not None:
            # JSON format
            return self._normalize_json(data, plan_id, step_index, result)

        # Raw console output
        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, str):
            return self._normalize_console(raw_output, plan_id, step_index, result)

        result.add_error("Unsupported Metasploit output format")
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
        result: PasserResult,
    ) -> PasserResult:
        """Normalize JSON format output."""
        result.raw_data = data

        # Handle module execution result
        if "result" in data or "job_id" in data:
            exec_result = self._parse_module_result(data, plan_id, step_index, result)
            if exec_result:
                result.execution_results.append(exec_result)

        # Handle sessions
        if "sessions" in data:
            for session_id, session_data in data["sessions"].items():
                exec_result = self._parse_session(
                    session_id, session_data, plan_id, step_index, result
                )
                if exec_result:
                    result.execution_results.append(exec_result)
                    step_index += 1

        # Handle module info
        if "module" in data or "module_name" in data:
            # This is module info, create observation
            observation = self._create_module_observation(data, result)
            if observation:
                result.observations.append(observation)

        return result

    def _normalize_console(
        self,
        output: str,
        plan_id: str,
        step_index: int,
        result: PasserResult,
    ) -> PasserResult:
        """Normalize raw console output."""
        # Determine success/failure
        status = self._determine_status(output)

        # Extract session info if present
        session_info = self._extract_session_info(output)

        # Extract error info if failed
        error_info = self._extract_error_info(output) if status == ExecutionStatus.FAILURE else None

        # Build output summary
        summary = self._build_summary(output, status, session_info)

        try:
            exec_result = ExecutionResult(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                plan_id=plan_id,
                step_index=step_index,
                status=status,
                output_summary=summary,
                raw_output_preview=output[:1000] if output else None,
                command_executed=self._extract_command(output),
                error_class=error_info.get("class") if error_info else None,
                error_message=error_info.get("message") if error_info else None,
                metadata={
                    "session_info": session_info,
                    "console_output_length": len(output),
                },
            )
            exec_result.mark_success() if status == ExecutionStatus.SUCCESS else None
            result.execution_results.append(exec_result)
        except Exception as e:
            result.add_error(f"Failed to create ExecutionResult: {e}")

        # Create observation
        observation = self._create_console_observation(output, status, result)
        if observation:
            result.observations.append(observation)

        return result

    def _parse_module_result(
        self,
        data: Dict[str, Any],
        plan_id: str,
        step_index: int,
        result: PasserResult,
    ) -> Optional[ExecutionResult]:
        """Parse module execution result from JSON."""
        try:
            # Determine status
            status = ExecutionStatus.SUCCESS
            error_class = None
            error_message = None

            if "error" in data:
                status = ExecutionStatus.FAILURE
                error_class = ErrorClass.TOOL_ERROR
                error_message = data.get("error_message") or str(data.get("error"))
            elif data.get("result") == "failure":
                status = ExecutionStatus.FAILURE
                error_class = ErrorClass.TOOL_ERROR

            # Build summary
            module_name = data.get("module_name") or data.get("module", {}).get("name", "unknown")
            summary = f"Module {module_name}: {status.value}"

            exec_result = ExecutionResult(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                plan_id=plan_id,
                step_index=step_index,
                status=status,
                output_summary=summary,
                command_executed=module_name,
                parameters_used=data.get("options", {}),
                error_class=error_class,
                error_message=error_message,
                exit_code=0 if status == ExecutionStatus.SUCCESS else 1,
                metadata={
                    "job_id": data.get("job_id"),
                    "uuid": data.get("uuid"),
                    "module_type": data.get("module_type"),
                    "payload": data.get("payload"),
                },
            )
            return exec_result
        except Exception as e:
            result.add_warning(f"Failed to parse module result: {e}")
            return None

    def _parse_session(
        self,
        session_id: str,
        session_data: Dict[str, Any],
        plan_id: str,
        step_index: int,
        result: PasserResult,
    ) -> Optional[ExecutionResult]:
        """Parse session info into ExecutionResult."""
        try:
            session_type = session_data.get("type", "shell")
            target = session_data.get("target_host") or session_data.get("tunnel_peer", "")

            summary = f"Session {session_id} ({session_type}) opened on {target}"

            exec_result = ExecutionResult(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                plan_id=plan_id,
                step_index=step_index,
                status=ExecutionStatus.SUCCESS,
                output_summary=summary,
                command_executed=session_data.get("via_exploit"),
                exit_code=0,
                metadata={
                    "msf_session_id": session_id,
                    "session_type": session_type,
                    "target_host": session_data.get("target_host"),
                    "tunnel_peer": session_data.get("tunnel_peer"),
                    "via_exploit": session_data.get("via_exploit"),
                    "via_payload": session_data.get("via_payload"),
                    "username": session_data.get("username"),
                    "platform": session_data.get("platform"),
                    "arch": session_data.get("arch"),
                },
            )
            return exec_result
        except Exception as e:
            result.add_warning(f"Failed to parse session: {e}")
            return None

    def _determine_status(self, output: str) -> ExecutionStatus:
        """Determine execution status from console output."""
        output_lower = output.lower()

        # Check for success patterns
        for pattern in self.SUCCESS_PATTERNS:
            if re.search(pattern, output_lower):
                return ExecutionStatus.SUCCESS

        # Check for failure patterns
        for pattern in self.FAILURE_PATTERNS:
            if re.search(pattern, output_lower):
                return ExecutionStatus.FAILURE

        # Default to partial if unclear
        return ExecutionStatus.PARTIAL

    def _extract_session_info(self, output: str) -> Optional[Dict[str, Any]]:
        """Extract session information from output."""
        # Look for session opened message
        session_match = re.search(
            r"(meterpreter|command shell) session (\d+) opened \(([^)]+)\)",
            output, re.IGNORECASE
        )
        if session_match:
            return {
                "type": session_match.group(1),
                "id": session_match.group(2),
                "connection": session_match.group(3),
            }
        return None

    def _extract_error_info(self, output: str) -> Dict[str, Any]:
        """Extract error information from output."""
        output_lower = output.lower()

        # Check for common error types
        if "connection refused" in output_lower or "connection timed out" in output_lower:
            return {"class": ErrorClass.NETWORK, "message": "Connection failed"}
        if "permission denied" in output_lower or "access denied" in output_lower:
            return {"class": ErrorClass.PERMISSION, "message": "Access denied"}
        if "timeout" in output_lower:
            return {"class": ErrorClass.TIMEOUT, "message": "Operation timed out"}
        if "not found" in output_lower:
            return {"class": ErrorClass.NOT_FOUND, "message": "Target not found"}

        # Extract specific error message
        error_match = re.search(r"\[-\]\s*(.+)", output)
        if error_match:
            return {"class": ErrorClass.TOOL_ERROR, "message": error_match.group(1)}

        return {"class": ErrorClass.UNKNOWN, "message": "Unknown error"}

    def _extract_command(self, output: str) -> Optional[str]:
        """Extract the command that was executed."""
        # Look for exploit/auxiliary/payload names
        module_match = re.search(
            r"(exploit|auxiliary|post)/[\w/]+",
            output, re.IGNORECASE
        )
        if module_match:
            return module_match.group(0)

        # Look for run/exploit command
        cmd_match = re.search(r"msf[^\>]*>\s*(\w+)", output)
        if cmd_match:
            return cmd_match.group(1)

        return None

    def _build_summary(
        self,
        output: str,
        status: ExecutionStatus,
        session_info: Optional[Dict[str, Any]],
    ) -> str:
        """Build execution summary."""
        if session_info:
            return f"Session {session_info['id']} opened ({session_info['type']})"

        if status == ExecutionStatus.SUCCESS:
            return "Metasploit module executed successfully"
        elif status == ExecutionStatus.FAILURE:
            return "Metasploit module execution failed"
        else:
            return "Metasploit module execution completed with partial results"

    def _create_module_observation(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create observation for module info."""
        try:
            module_data = data.get("module", data)
            module_name = module_data.get("name") or module_data.get("module_name", "unknown")
            module_type = module_data.get("type") or module_data.get("module_type", "unknown")

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="module_info",
                summary=f"Module info: {module_type}/{module_name}",
                success=True,
                metadata={
                    "module_name": module_name,
                    "module_type": module_type,
                    "description": module_data.get("description"),
                    "rank": module_data.get("rank"),
                    "references": module_data.get("references", []),
                },
            )
            return observation
        except Exception as e:
            result.add_warning(f"Failed to create module observation: {e}")
            return None

    def _create_console_observation(
        self,
        output: str,
        status: ExecutionStatus,
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create observation for console output."""
        try:
            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="module_execution",
                summary=f"Metasploit execution: {status.value}",
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
            result.add_warning(f"Failed to create console observation: {e}")
            return None
