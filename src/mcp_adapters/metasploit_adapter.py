"""
Metasploit MCP Adapter for PentestAgent.

Provides interface to Metasploit MCP for exploitation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError, MCPToolType


class MetasploitAdapter(BaseMCPAdapter):
    """
    Adapter for Metasploit MCP.

    Provides exploitation capabilities:
    - Module search and selection
    - Exploit execution
    - Session management
    - Post-exploitation commands
    """

    # Supported operations
    OPERATIONS = [
        "search_modules",       # Search for exploit modules
        "get_module_info",      # Get module details
        "set_options",          # Set module options
        "execute_exploit",      # Execute an exploit
        "check_vuln",           # Check if target is vulnerable
        "list_sessions",        # List active sessions
        "session_command",      # Run command in session
        "close_session",        # Close a session
        "get_payloads",         # Get compatible payloads
    ]

    # Dangerous operations requiring extra verification
    DANGEROUS_OPERATIONS = [
        "execute_exploit",
        "session_command",
    ]

    def __init__(
        self,
        timeout_seconds: int = 300,
        max_retries: int = 1,
        mock_mode: bool = False,
    ):
        """
        Initialize Metasploit adapter.

        Args:
            timeout_seconds: Timeout for operations.
            max_retries: Maximum retry attempts.
            mock_mode: If True, return mock data instead of calling MCP.
        """
        super().__init__(
            tool_type=MCPToolType.MSF,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
        self.mock_mode = mock_mode
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

    def get_supported_operations(self) -> List[str]:
        """Get list of supported operations."""
        return self.OPERATIONS.copy()

    def is_dangerous_operation(self, operation: str) -> bool:
        """Check if operation is dangerous."""
        return operation in self.DANGEROUS_OPERATIONS

    def _invoke_tool(
        self,
        operation: str,
        params: Dict[str, Any],
    ) -> MCPResult:
        """
        Invoke Metasploit MCP tool.

        Args:
            operation: Operation to perform.
            params: Parameters for the operation.

        Returns:
            MCPResult with the result.
        """
        if operation not in self.OPERATIONS:
            raise MCPError(
                f"Unsupported operation: {operation}",
                tool=self.tool_name,
                operation=operation,
            )

        if self.mock_mode:
            return self._mock_invoke(operation, params)

        return self._mcp_invoke(operation, params)

    def _mcp_invoke(
        self,
        operation: str,
        params: Dict[str, Any],
    ) -> MCPResult:
        """Invoke Metasploit via MCP - placeholder."""
        raise MCPError(
            "MCP integration not yet implemented. Use mock_mode=True for testing.",
            tool=self.tool_name,
            operation=operation,
            retryable=False,
        )

    def _mock_invoke(
        self,
        operation: str,
        params: Dict[str, Any],
    ) -> MCPResult:
        """Return mock data for testing."""
        mock_handlers = {
            "search_modules": self._mock_search_modules,
            "get_module_info": self._mock_get_module_info,
            "set_options": self._mock_set_options,
            "execute_exploit": self._mock_execute_exploit,
            "check_vuln": self._mock_check_vuln,
            "list_sessions": self._mock_list_sessions,
            "session_command": self._mock_session_command,
            "close_session": self._mock_close_session,
            "get_payloads": self._mock_get_payloads,
        }

        handler = mock_handlers.get(operation)
        if handler:
            return handler(params)

        raise MCPError(
            f"Mock not implemented for: {operation}",
            tool=self.tool_name,
            operation=operation,
        )

    def _mock_search_modules(self, params: Dict[str, Any]) -> MCPResult:
        """Mock module search response."""
        query = params.get("query", "")
        module_type = params.get("type", "exploit")

        return MCPResult(
            tool=self.tool_name,
            operation="search_modules",
            success=True,
            data={
                "query": query,
                "type": module_type,
                "modules": [
                    {
                        "name": "exploit/multi/http/log4shell_header_injection",
                        "fullname": "exploit/multi/http/log4shell_header_injection",
                        "rank": "excellent",
                        "description": "Apache Log4j RCE via JNDI Injection",
                        "platform": ["unix", "windows"],
                        "arch": ["x86", "x64"],
                        "references": ["CVE-2021-44228"],
                    },
                    {
                        "name": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
                        "fullname": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
                        "rank": "excellent",
                        "description": "Apache mod_cgi Bash Environment Variable Injection",
                        "platform": ["unix"],
                        "arch": ["cmd"],
                        "references": ["CVE-2014-6271"],
                    },
                ],
                "total": 2,
            },
            metadata={"source": "metasploit", "operation": "search_modules"},
        )

    def _mock_get_module_info(self, params: Dict[str, Any]) -> MCPResult:
        """Mock module info response."""
        module = params.get("module", "")

        return MCPResult(
            tool=self.tool_name,
            operation="get_module_info",
            success=True,
            data={
                "name": module,
                "type": "exploit",
                "rank": "excellent",
                "description": "Apache Log4j Remote Code Execution",
                "author": ["mbechler"],
                "license": "Metasploit Framework License (BSD)",
                "platform": ["unix", "windows"],
                "arch": ["x86", "x64"],
                "references": [
                    {"type": "CVE", "ref": "2021-44228"},
                    {"type": "URL", "ref": "https://logging.apache.org/log4j/2.x/security.html"},
                ],
                "options": {
                    "RHOSTS": {"required": True, "description": "Target addresses"},
                    "RPORT": {"required": True, "default": 8080, "description": "Target port"},
                    "TARGETURI": {"required": True, "default": "/", "description": "Target URI"},
                    "HTTP_HEADER": {"required": False, "default": "X-Api-Version", "description": "Header to inject"},
                },
                "targets": [
                    {"id": 0, "name": "Unix Command"},
                    {"id": 1, "name": "Linux Dropper"},
                    {"id": 2, "name": "Windows Command"},
                ],
                "default_target": 0,
            },
            metadata={"source": "metasploit", "operation": "get_module_info"},
        )

    def _mock_set_options(self, params: Dict[str, Any]) -> MCPResult:
        """Mock set options response."""
        module = params.get("module", "")
        options = params.get("options", {})

        return MCPResult(
            tool=self.tool_name,
            operation="set_options",
            success=True,
            data={
                "module": module,
                "options_set": options,
                "validation": {
                    "valid": True,
                    "missing_required": [],
                    "warnings": [],
                },
            },
            metadata={"source": "metasploit", "operation": "set_options"},
        )

    def _mock_execute_exploit(self, params: Dict[str, Any]) -> MCPResult:
        """Mock exploit execution response."""
        module = params.get("module", "")
        target = params.get("target", "")
        dry_run = params.get("dry_run", False)

        if dry_run:
            return MCPResult(
                tool=self.tool_name,
                operation="execute_exploit",
                success=True,
                data={
                    "module": module,
                    "target": target,
                    "dry_run": True,
                    "would_execute": True,
                    "command_preview": f"use {module}; set RHOSTS {target}; exploit",
                },
                metadata={"source": "metasploit", "operation": "execute_exploit"},
            )

        # Simulate successful exploitation
        session_id = f"session-{len(self._active_sessions) + 1}"
        self._active_sessions[session_id] = {
            "id": session_id,
            "type": "meterpreter",
            "target": target,
            "created_at": datetime.utcnow().isoformat(),
        }

        return MCPResult(
            tool=self.tool_name,
            operation="execute_exploit",
            success=True,
            data={
                "module": module,
                "target": target,
                "result": "success",
                "session_id": session_id,
                "session_type": "meterpreter",
                "output": "[*] Started reverse TCP handler\n[*] Sending payload...\n[+] Meterpreter session opened",
            },
            metadata={"source": "metasploit", "operation": "execute_exploit"},
        )

    def _mock_check_vuln(self, params: Dict[str, Any]) -> MCPResult:
        """Mock vulnerability check response."""
        module = params.get("module", "")
        target = params.get("target", "")

        return MCPResult(
            tool=self.tool_name,
            operation="check_vuln",
            success=True,
            data={
                "module": module,
                "target": target,
                "vulnerable": True,
                "confidence": "high",
                "details": "Target appears to be vulnerable based on version fingerprint",
                "check_output": "[+] The target appears to be vulnerable.",
            },
            metadata={"source": "metasploit", "operation": "check_vuln"},
        )

    def _mock_list_sessions(self, params: Dict[str, Any]) -> MCPResult:
        """Mock list sessions response."""
        return MCPResult(
            tool=self.tool_name,
            operation="list_sessions",
            success=True,
            data={
                "sessions": list(self._active_sessions.values()),
                "total": len(self._active_sessions),
            },
            metadata={"source": "metasploit", "operation": "list_sessions"},
        )

    def _mock_session_command(self, params: Dict[str, Any]) -> MCPResult:
        """Mock session command response."""
        session_id = params.get("session_id", "")
        command = params.get("command", "")

        if session_id not in self._active_sessions:
            return MCPResult(
                tool=self.tool_name,
                operation="session_command",
                success=False,
                error=f"Session {session_id} not found",
            )

        # Mock command output
        outputs = {
            "whoami": "www-data",
            "id": "uid=33(www-data) gid=33(www-data) groups=33(www-data)",
            "pwd": "/var/www/html",
            "uname -a": "Linux webapp 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux",
        }

        return MCPResult(
            tool=self.tool_name,
            operation="session_command",
            success=True,
            data={
                "session_id": session_id,
                "command": command,
                "output": outputs.get(command, f"Command executed: {command}"),
            },
            metadata={"source": "metasploit", "operation": "session_command"},
        )

    def _mock_close_session(self, params: Dict[str, Any]) -> MCPResult:
        """Mock close session response."""
        session_id = params.get("session_id", "")

        if session_id in self._active_sessions:
            del self._active_sessions[session_id]

        return MCPResult(
            tool=self.tool_name,
            operation="close_session",
            success=True,
            data={
                "session_id": session_id,
                "closed": True,
            },
            metadata={"source": "metasploit", "operation": "close_session"},
        )

    def _mock_get_payloads(self, params: Dict[str, Any]) -> MCPResult:
        """Mock get payloads response."""
        module = params.get("module", "")
        target_platform = params.get("platform", "")

        return MCPResult(
            tool=self.tool_name,
            operation="get_payloads",
            success=True,
            data={
                "module": module,
                "platform": target_platform,
                "payloads": [
                    {
                        "name": "linux/x64/meterpreter/reverse_tcp",
                        "rank": "normal",
                        "description": "Inject the mettle server payload (staged)",
                    },
                    {
                        "name": "linux/x64/shell/reverse_tcp",
                        "rank": "normal",
                        "description": "Spawn a command shell (staged)",
                    },
                    {
                        "name": "cmd/unix/reverse_bash",
                        "rank": "normal",
                        "description": "Unix reverse shell using Bash",
                    },
                ],
                "total": 3,
            },
            metadata={"source": "metasploit", "operation": "get_payloads"},
        )

    # Convenience methods

    def search_modules(
        self,
        query: str,
        module_type: str = "exploit",
    ) -> MCPResult:
        """
        Search for Metasploit modules.

        Args:
            query: Search query
            module_type: Type of module (exploit, auxiliary, post)

        Returns:
            MCPResult with matching modules.
        """
        return self.invoke("search_modules", {"query": query, "type": module_type})

    def get_module_info(self, module: str) -> MCPResult:
        """
        Get module information.

        Args:
            module: Module full name

        Returns:
            MCPResult with module details.
        """
        return self.invoke("get_module_info", {"module": module})

    def set_options(
        self,
        module: str,
        options: Dict[str, Any],
    ) -> MCPResult:
        """
        Set module options.

        Args:
            module: Module name
            options: Options to set

        Returns:
            MCPResult with validation info.
        """
        return self.invoke("set_options", {"module": module, "options": options})

    def execute_exploit(
        self,
        module: str,
        target: str,
        options: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
    ) -> MCPResult:
        """
        Execute an exploit.

        Args:
            module: Exploit module
            target: Target host
            options: Module options
            dry_run: If True, only simulate

        Returns:
            MCPResult with execution result.
        """
        params = {
            "module": module,
            "target": target,
            "dry_run": dry_run,
        }
        if options:
            params["options"] = options
        return self.invoke("execute_exploit", params)

    def check_vulnerability(
        self,
        module: str,
        target: str,
    ) -> MCPResult:
        """
        Check if target is vulnerable.

        Args:
            module: Exploit module
            target: Target host

        Returns:
            MCPResult with vulnerability status.
        """
        return self.invoke("check_vuln", {"module": module, "target": target})

    def list_sessions(self) -> MCPResult:
        """
        List active sessions.

        Returns:
            MCPResult with sessions.
        """
        return self.invoke("list_sessions", {})

    def run_session_command(
        self,
        session_id: str,
        command: str,
    ) -> MCPResult:
        """
        Run command in session.

        Args:
            session_id: Session ID
            command: Command to run

        Returns:
            MCPResult with command output.
        """
        return self.invoke("session_command", {
            "session_id": session_id,
            "command": command,
        })

    def close_session(self, session_id: str) -> MCPResult:
        """
        Close a session.

        Args:
            session_id: Session to close

        Returns:
            MCPResult with closure status.
        """
        return self.invoke("close_session", {"session_id": session_id})

    def get_payloads(
        self,
        module: str,
        platform: Optional[str] = None,
    ) -> MCPResult:
        """
        Get compatible payloads for module.

        Args:
            module: Exploit module
            platform: Target platform filter

        Returns:
            MCPResult with payloads.
        """
        params = {"module": module}
        if platform:
            params["platform"] = platform
        return self.invoke("get_payloads", params)
