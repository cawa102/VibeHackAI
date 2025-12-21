"""
Kali MCP Adapter for PentestAgent.

Provides interface to Kali tools via MCP.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError, MCPToolType


class KaliAdapter(BaseMCPAdapter):
    """
    Adapter for Kali MCP Server.

    Provides access to various Kali Linux tools:
    - SQLMap for SQL injection testing
    - Nikto for web server scanning
    - Hydra for credential testing
    - Custom tool execution
    """

    # Supported operations
    OPERATIONS = [
        "sqlmap_scan",          # SQL injection testing
        "nikto_scan",           # Web server scanning
        "hydra_attack",         # Credential brute-force
        "dirb_scan",            # Directory enumeration
        "wfuzz_scan",           # Web fuzzing
        "run_tool",             # Run arbitrary tool
        "list_tools",           # List available tools
        "get_tool_help",        # Get tool help
    ]

    # Dangerous operations requiring approval
    DANGEROUS_OPERATIONS = [
        "sqlmap_scan",
        "hydra_attack",
        "run_tool",
    ]

    # Allowed tools for run_tool
    ALLOWED_TOOLS = [
        "curl",
        "wget",
        "nmap",
        "sqlmap",
        "nikto",
        "dirb",
        "wfuzz",
        "whatweb",
        "wpscan",
    ]

    def __init__(
        self,
        timeout_seconds: int = 300,
        max_retries: int = 1,
        mock_mode: bool = False,
    ):
        """
        Initialize Kali adapter.

        Args:
            timeout_seconds: Timeout for operations.
            max_retries: Maximum retry attempts.
            mock_mode: If True, return mock data instead of calling MCP.
        """
        super().__init__(
            tool_type=MCPToolType.KALI,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
        self.mock_mode = mock_mode

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
        Invoke Kali MCP tool.

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
        """Invoke Kali tool via MCP - placeholder."""
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
            "sqlmap_scan": self._mock_sqlmap_scan,
            "nikto_scan": self._mock_nikto_scan,
            "hydra_attack": self._mock_hydra_attack,
            "dirb_scan": self._mock_dirb_scan,
            "wfuzz_scan": self._mock_wfuzz_scan,
            "run_tool": self._mock_run_tool,
            "list_tools": self._mock_list_tools,
            "get_tool_help": self._mock_get_tool_help,
        }

        handler = mock_handlers.get(operation)
        if handler:
            return handler(params)

        raise MCPError(
            f"Mock not implemented for: {operation}",
            tool=self.tool_name,
            operation=operation,
        )

    def _mock_sqlmap_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock SQLMap scan response."""
        target = params.get("target", "")
        parameter = params.get("parameter", "")
        technique = params.get("technique", "BEUSTQ")

        return MCPResult(
            tool=self.tool_name,
            operation="sqlmap_scan",
            success=True,
            data={
                "target": target,
                "parameter": parameter,
                "vulnerable": True,
                "injection_type": "boolean-based blind",
                "dbms": "MySQL",
                "dbms_version": "5.7.32",
                "technique": technique,
                "payload": f"' AND 1=1 AND '{parameter}'='{parameter}",
                "details": {
                    "title": "AND boolean-based blind - WHERE or HAVING clause",
                    "vector": "[AND [RANDNUM]=[RANDNUM]]",
                },
                "databases": ["information_schema", "webapp_db"],
                "output": "[INFO] testing connection to the target URL\n[INFO] testing if the target URL is stable\n[INFO] testing 'AND boolean-based blind' injection\n[+] Parameter appears to be vulnerable!",
            },
            metadata={"source": "kali", "tool": "sqlmap"},
        )

    def _mock_nikto_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock Nikto scan response."""
        target = params.get("target", "")

        return MCPResult(
            tool=self.tool_name,
            operation="nikto_scan",
            success=True,
            data={
                "target": target,
                "server": "Apache/2.4.49",
                "findings": [
                    {
                        "id": "OSVDB-3092",
                        "method": "GET",
                        "uri": "/admin/",
                        "description": "Directory indexing found",
                        "severity": "medium",
                    },
                    {
                        "id": "OSVDB-3268",
                        "method": "GET",
                        "uri": "/icons/",
                        "description": "Default Apache icons directory found",
                        "severity": "low",
                    },
                    {
                        "id": "CVE-2021-41773",
                        "method": "GET",
                        "uri": "/cgi-bin/.%2e/%2e%2e/etc/passwd",
                        "description": "Apache 2.4.49 Path Traversal",
                        "severity": "critical",
                    },
                ],
                "total_findings": 3,
                "scan_time": "45 seconds",
            },
            metadata={"source": "kali", "tool": "nikto"},
        )

    def _mock_hydra_attack(self, params: Dict[str, Any]) -> MCPResult:
        """Mock Hydra attack response."""
        target = params.get("target", "")
        service = params.get("service", "http-post-form")
        username = params.get("username", "admin")

        return MCPResult(
            tool=self.tool_name,
            operation="hydra_attack",
            success=True,
            data={
                "target": target,
                "service": service,
                "username": username,
                "success": True,
                "credentials": {
                    "username": username,
                    "password": "admin123",
                },
                "attempts": 127,
                "time_elapsed": "12 seconds",
                "output": f"[DATA] attacking {service}://{target}\n[STATUS] 127 tries in 0:00:12\n[{service}] host: {target}   login: {username}   password: admin123",
            },
            metadata={"source": "kali", "tool": "hydra"},
        )

    def _mock_dirb_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock DIRB scan response."""
        target = params.get("target", "")
        wordlist = params.get("wordlist", "/usr/share/dirb/wordlists/common.txt")

        return MCPResult(
            tool=self.tool_name,
            operation="dirb_scan",
            success=True,
            data={
                "target": target,
                "wordlist": wordlist,
                "directories_found": [
                    {"url": f"{target}/admin", "code": 200, "size": 4521},
                    {"url": f"{target}/backup", "code": 403, "size": 287},
                    {"url": f"{target}/config", "code": 200, "size": 1234},
                    {"url": f"{target}/uploads", "code": 200, "size": 892},
                ],
                "files_found": [
                    {"url": f"{target}/robots.txt", "code": 200, "size": 156},
                    {"url": f"{target}/.htaccess", "code": 403, "size": 287},
                ],
                "total_found": 6,
                "words_checked": 4614,
            },
            metadata={"source": "kali", "tool": "dirb"},
        )

    def _mock_wfuzz_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock WFuzz scan response."""
        target = params.get("target", "")
        fuzz_point = params.get("fuzz_point", "FUZZ")

        return MCPResult(
            tool=self.tool_name,
            operation="wfuzz_scan",
            success=True,
            data={
                "target": target,
                "fuzz_point": fuzz_point,
                "results": [
                    {"payload": "admin", "code": 200, "lines": 45, "words": 234},
                    {"payload": "test", "code": 200, "lines": 12, "words": 89},
                    {"payload": "backup", "code": 403, "lines": 7, "words": 42},
                ],
                "total_requests": 100,
                "interesting_responses": 3,
            },
            metadata={"source": "kali", "tool": "wfuzz"},
        )

    def _mock_run_tool(self, params: Dict[str, Any]) -> MCPResult:
        """Mock run tool response."""
        tool = params.get("tool", "")
        args = params.get("args", [])

        if tool not in self.ALLOWED_TOOLS:
            return MCPResult(
                tool=self.tool_name,
                operation="run_tool",
                success=False,
                error=f"Tool not allowed: {tool}",
            )

        return MCPResult(
            tool=self.tool_name,
            operation="run_tool",
            success=True,
            data={
                "tool": tool,
                "args": args,
                "command": f"{tool} {' '.join(args)}",
                "exit_code": 0,
                "stdout": f"Mock output for {tool}",
                "stderr": "",
            },
            metadata={"source": "kali", "tool": tool},
        )

    def _mock_list_tools(self, params: Dict[str, Any]) -> MCPResult:
        """Mock list tools response."""
        return MCPResult(
            tool=self.tool_name,
            operation="list_tools",
            success=True,
            data={
                "tools": [
                    {"name": "sqlmap", "category": "sql_injection", "description": "Automatic SQL injection tool"},
                    {"name": "nikto", "category": "web_scanner", "description": "Web server scanner"},
                    {"name": "hydra", "category": "password", "description": "Password cracking tool"},
                    {"name": "dirb", "category": "enumeration", "description": "Directory brute forcer"},
                    {"name": "wfuzz", "category": "fuzzing", "description": "Web application fuzzer"},
                    {"name": "nmap", "category": "network", "description": "Network scanner"},
                ],
                "total": 6,
            },
            metadata={"source": "kali", "operation": "list_tools"},
        )

    def _mock_get_tool_help(self, params: Dict[str, Any]) -> MCPResult:
        """Mock get tool help response."""
        tool = params.get("tool", "")

        help_texts = {
            "sqlmap": "sqlmap [-u URL] [-p PARAMETER] [--dbs] [--tables] [--dump]",
            "nikto": "nikto -h HOST [-port PORT] [-ssl]",
            "hydra": "hydra [-l LOGIN] [-P PASSLIST] HOST SERVICE",
        }

        return MCPResult(
            tool=self.tool_name,
            operation="get_tool_help",
            success=True,
            data={
                "tool": tool,
                "help": help_texts.get(tool, f"Help for {tool}"),
                "examples": [
                    f"{tool} --help",
                    f"man {tool}",
                ],
            },
            metadata={"source": "kali", "operation": "get_tool_help"},
        )

    # Convenience methods

    def sqlmap_scan(
        self,
        target: str,
        parameter: Optional[str] = None,
        technique: str = "BEUSTQ",
        level: int = 1,
        risk: int = 1,
    ) -> MCPResult:
        """
        Run SQLMap scan.

        Args:
            target: Target URL
            parameter: Parameter to test
            technique: Injection techniques
            level: Test level (1-5)
            risk: Risk level (1-3)

        Returns:
            MCPResult with scan results.
        """
        params = {
            "target": target,
            "technique": technique,
            "level": level,
            "risk": risk,
        }
        if parameter:
            params["parameter"] = parameter
        return self.invoke("sqlmap_scan", params)

    def nikto_scan(
        self,
        target: str,
        port: int = 80,
        ssl: bool = False,
    ) -> MCPResult:
        """
        Run Nikto scan.

        Args:
            target: Target host
            port: Target port
            ssl: Use SSL

        Returns:
            MCPResult with scan results.
        """
        return self.invoke("nikto_scan", {
            "target": target,
            "port": port,
            "ssl": ssl,
        })

    def hydra_attack(
        self,
        target: str,
        service: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        passlist: Optional[str] = None,
    ) -> MCPResult:
        """
        Run Hydra credential attack.

        Args:
            target: Target host
            service: Service to attack
            username: Single username
            userlist: Username wordlist
            passlist: Password wordlist

        Returns:
            MCPResult with attack results.
        """
        params = {
            "target": target,
            "service": service,
        }
        if username:
            params["username"] = username
        if userlist:
            params["userlist"] = userlist
        if passlist:
            params["passlist"] = passlist
        return self.invoke("hydra_attack", params)

    def dirb_scan(
        self,
        target: str,
        wordlist: Optional[str] = None,
    ) -> MCPResult:
        """
        Run DIRB directory enumeration.

        Args:
            target: Target URL
            wordlist: Wordlist to use

        Returns:
            MCPResult with discovered directories.
        """
        params = {"target": target}
        if wordlist:
            params["wordlist"] = wordlist
        return self.invoke("dirb_scan", params)

    def wfuzz_scan(
        self,
        target: str,
        wordlist: str,
        fuzz_point: str = "FUZZ",
    ) -> MCPResult:
        """
        Run WFuzz scan.

        Args:
            target: Target URL with FUZZ marker
            wordlist: Wordlist to use
            fuzz_point: Fuzz marker

        Returns:
            MCPResult with fuzz results.
        """
        return self.invoke("wfuzz_scan", {
            "target": target,
            "wordlist": wordlist,
            "fuzz_point": fuzz_point,
        })

    def run_tool(
        self,
        tool: str,
        args: List[str],
    ) -> MCPResult:
        """
        Run a Kali tool.

        Args:
            tool: Tool name
            args: Tool arguments

        Returns:
            MCPResult with tool output.
        """
        return self.invoke("run_tool", {"tool": tool, "args": args})

    def list_tools(self) -> MCPResult:
        """
        List available tools.

        Returns:
            MCPResult with tool list.
        """
        return self.invoke("list_tools", {})

    def get_tool_help(self, tool: str) -> MCPResult:
        """
        Get help for a tool.

        Args:
            tool: Tool name

        Returns:
            MCPResult with help text.
        """
        return self.invoke("get_tool_help", {"tool": tool})
