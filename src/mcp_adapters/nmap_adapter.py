"""
Nmap MCP Adapter for PentestAgent.

Provides interface to Nmap MCP for active reconnaissance.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError, MCPToolType


class NmapAdapter(BaseMCPAdapter):
    """
    Adapter for Nmap MCP.

    Provides active reconnaissance capabilities:
    - Port scanning
    - Service detection
    - OS fingerprinting
    - Script scanning
    """

    # Supported operations
    OPERATIONS = [
        "port_scan",        # Basic port scan
        "service_scan",     # Service/version detection
        "os_detect",        # OS fingerprinting
        "script_scan",      # NSE script scanning
        "quick_scan",       # Fast scan of common ports
        "stealth_scan",     # SYN stealth scan
        "udp_scan",         # UDP port scan
    ]

    # Default scan profiles
    SCAN_PROFILES = {
        "quick": {
            "ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
            "timing": "T3",
        },
        "stealth": {
            "ports": "1-1000",
            "timing": "T2",
            "flags": "-sS",
        },
        "comprehensive": {
            "ports": "1-65535",
            "timing": "T3",
            "flags": "-sV -sC",
        },
        "minimal": {
            "ports": "22,80,443",
            "timing": "T2",
        },
    }

    def __init__(
        self,
        timeout_seconds: int = 300,  # 5 minutes for scans
        max_retries: int = 1,
        mock_mode: bool = False,
        default_profile: str = "minimal",
    ):
        """
        Initialize Nmap adapter.

        Args:
            timeout_seconds: Timeout for operations.
            max_retries: Maximum retry attempts.
            mock_mode: If True, return mock data instead of calling MCP.
            default_profile: Default scan profile to use.
        """
        super().__init__(
            tool_type=MCPToolType.NMAP,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
        self.mock_mode = mock_mode
        self.default_profile = default_profile

    def get_supported_operations(self) -> List[str]:
        """Get list of supported operations."""
        return self.OPERATIONS.copy()

    def get_scan_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Get available scan profiles."""
        return self.SCAN_PROFILES.copy()

    def _invoke_tool(
        self,
        operation: str,
        params: Dict[str, Any],
    ) -> MCPResult:
        """
        Invoke Nmap MCP tool.

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
        """
        Invoke Nmap via MCP.

        This is a placeholder for actual MCP integration.
        """
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
            "port_scan": self._mock_port_scan,
            "service_scan": self._mock_service_scan,
            "os_detect": self._mock_os_detect,
            "script_scan": self._mock_script_scan,
            "quick_scan": self._mock_quick_scan,
            "stealth_scan": self._mock_stealth_scan,
            "udp_scan": self._mock_udp_scan,
        }

        handler = mock_handlers.get(operation)
        if handler:
            return handler(params)

        raise MCPError(
            f"Mock not implemented for: {operation}",
            tool=self.tool_name,
            operation=operation,
        )

    def _mock_port_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock port scan response."""
        target = params.get("target", "192.168.1.1")
        ports = params.get("ports", "22,80,443")

        return MCPResult(
            tool=self.tool_name,
            operation="port_scan",
            success=True,
            data={
                "target": target,
                "host_status": "up",
                "latency": "0.015s",
                "ports": [
                    {"port": 22, "state": "open", "protocol": "tcp"},
                    {"port": 80, "state": "open", "protocol": "tcp"},
                    {"port": 443, "state": "open", "protocol": "tcp"},
                ],
                "scan_info": {
                    "type": "syn",
                    "ports_scanned": ports,
                    "timing": "T3",
                },
            },
            raw_output="Starting Nmap 7.94 ...\nNmap scan report for 192.168.1.1\nHost is up (0.015s latency).\nPORT    STATE SERVICE\n22/tcp  open  ssh\n80/tcp  open  http\n443/tcp open  https",
            metadata={"source": "nmap", "scan_type": "port_scan"},
        )

    def _mock_service_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock service scan response."""
        target = params.get("target", "192.168.1.1")

        return MCPResult(
            tool=self.tool_name,
            operation="service_scan",
            success=True,
            data={
                "target": target,
                "host_status": "up",
                "ports": [
                    {
                        "port": 22,
                        "state": "open",
                        "protocol": "tcp",
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "8.4p1",
                        "extrainfo": "Debian 5",
                        "cpe": "cpe:/a:openbsd:openssh:8.4p1",
                    },
                    {
                        "port": 80,
                        "state": "open",
                        "protocol": "tcp",
                        "service": "http",
                        "product": "nginx",
                        "version": "1.18.0",
                        "cpe": "cpe:/a:nginx:nginx:1.18.0",
                    },
                    {
                        "port": 443,
                        "state": "open",
                        "protocol": "tcp",
                        "service": "ssl/http",
                        "product": "nginx",
                        "version": "1.18.0",
                        "tunnel": "ssl",
                        "cpe": "cpe:/a:nginx:nginx:1.18.0",
                    },
                ],
            },
            metadata={"source": "nmap", "scan_type": "service_scan"},
        )

    def _mock_os_detect(self, params: Dict[str, Any]) -> MCPResult:
        """Mock OS detection response."""
        target = params.get("target", "192.168.1.1")

        return MCPResult(
            tool=self.tool_name,
            operation="os_detect",
            success=True,
            data={
                "target": target,
                "os_matches": [
                    {
                        "name": "Linux 5.4 - 5.10",
                        "accuracy": 95,
                        "cpe": "cpe:/o:linux:linux_kernel:5",
                    },
                    {
                        "name": "Linux 4.15 - 5.8",
                        "accuracy": 90,
                        "cpe": "cpe:/o:linux:linux_kernel:4",
                    },
                ],
                "os_fingerprint": {
                    "class": "Linux",
                    "vendor": "Linux",
                    "family": "Linux",
                    "generation": "5.X",
                },
                "device_type": "general purpose",
                "network_distance": 1,
            },
            metadata={"source": "nmap", "scan_type": "os_detect"},
        )

    def _mock_script_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock NSE script scan response."""
        target = params.get("target", "192.168.1.1")
        scripts = params.get("scripts", "default")

        return MCPResult(
            tool=self.tool_name,
            operation="script_scan",
            success=True,
            data={
                "target": target,
                "script_results": [
                    {
                        "port": 22,
                        "script": "ssh-hostkey",
                        "output": "2048 RSA key fingerprint...",
                    },
                    {
                        "port": 80,
                        "script": "http-title",
                        "output": "Welcome to nginx",
                    },
                    {
                        "port": 80,
                        "script": "http-server-header",
                        "output": "nginx/1.18.0",
                    },
                    {
                        "port": 443,
                        "script": "ssl-cert",
                        "output": "Subject: CN=example.com\nIssuer: CN=Let's Encrypt",
                    },
                ],
            },
            metadata={"source": "nmap", "scan_type": "script_scan", "scripts": scripts},
        )

    def _mock_quick_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock quick scan response."""
        target = params.get("target", "192.168.1.1")

        return MCPResult(
            tool=self.tool_name,
            operation="quick_scan",
            success=True,
            data={
                "target": target,
                "host_status": "up",
                "ports": [
                    {"port": 22, "state": "open", "service": "ssh"},
                    {"port": 80, "state": "open", "service": "http"},
                    {"port": 443, "state": "open", "service": "https"},
                    {"port": 3306, "state": "filtered", "service": "mysql"},
                ],
                "scan_time": "2.5s",
            },
            metadata={"source": "nmap", "scan_type": "quick_scan"},
        )

    def _mock_stealth_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock stealth scan response."""
        target = params.get("target", "192.168.1.1")

        return MCPResult(
            tool=self.tool_name,
            operation="stealth_scan",
            success=True,
            data={
                "target": target,
                "host_status": "up",
                "ports": [
                    {"port": 22, "state": "open", "protocol": "tcp"},
                    {"port": 80, "state": "open", "protocol": "tcp"},
                    {"port": 443, "state": "open", "protocol": "tcp"},
                ],
                "scan_info": {
                    "type": "syn",
                    "timing": "T2",
                    "stealth": True,
                },
            },
            metadata={"source": "nmap", "scan_type": "stealth_scan"},
        )

    def _mock_udp_scan(self, params: Dict[str, Any]) -> MCPResult:
        """Mock UDP scan response."""
        target = params.get("target", "192.168.1.1")

        return MCPResult(
            tool=self.tool_name,
            operation="udp_scan",
            success=True,
            data={
                "target": target,
                "host_status": "up",
                "ports": [
                    {"port": 53, "state": "open", "protocol": "udp", "service": "dns"},
                    {"port": 123, "state": "open", "protocol": "udp", "service": "ntp"},
                    {"port": 161, "state": "open|filtered", "protocol": "udp", "service": "snmp"},
                ],
            },
            metadata={"source": "nmap", "scan_type": "udp_scan"},
        )

    # Convenience methods

    def port_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        timing: str = "T3",
    ) -> MCPResult:
        """
        Perform basic port scan.

        Args:
            target: Target IP or hostname.
            ports: Port specification (e.g., "22,80,443" or "1-1000").
            timing: Timing template (T0-T5).

        Returns:
            MCPResult with port scan results.
        """
        profile = self.SCAN_PROFILES.get(self.default_profile, {})
        params = {
            "target": target,
            "ports": ports or profile.get("ports", "22,80,443"),
            "timing": timing,
        }
        return self.invoke("port_scan", params)

    def service_scan(
        self,
        target: str,
        ports: Optional[str] = None,
    ) -> MCPResult:
        """
        Scan with service/version detection.

        Args:
            target: Target IP or hostname.
            ports: Port specification.

        Returns:
            MCPResult with service detection results.
        """
        params = {"target": target}
        if ports:
            params["ports"] = ports
        return self.invoke("service_scan", params)

    def os_detect(self, target: str) -> MCPResult:
        """
        Perform OS fingerprinting.

        Args:
            target: Target IP or hostname.

        Returns:
            MCPResult with OS detection results.
        """
        return self.invoke("os_detect", {"target": target})

    def script_scan(
        self,
        target: str,
        scripts: str = "default",
        ports: Optional[str] = None,
    ) -> MCPResult:
        """
        Run NSE scripts.

        Args:
            target: Target IP or hostname.
            scripts: Script selection (e.g., "default", "vuln", "safe").
            ports: Port specification.

        Returns:
            MCPResult with script results.
        """
        params = {"target": target, "scripts": scripts}
        if ports:
            params["ports"] = ports
        return self.invoke("script_scan", params)

    def quick_scan(self, target: str) -> MCPResult:
        """
        Perform quick scan of common ports.

        Args:
            target: Target IP or hostname.

        Returns:
            MCPResult with quick scan results.
        """
        return self.invoke("quick_scan", {"target": target})

    def stealth_scan(
        self,
        target: str,
        ports: Optional[str] = None,
    ) -> MCPResult:
        """
        Perform SYN stealth scan.

        Args:
            target: Target IP or hostname.
            ports: Port specification.

        Returns:
            MCPResult with stealth scan results.
        """
        params = {"target": target}
        if ports:
            params["ports"] = ports
        return self.invoke("stealth_scan", params)

    def udp_scan(
        self,
        target: str,
        ports: str = "53,67,68,69,123,137,138,139,161,162,500,514,520",
    ) -> MCPResult:
        """
        Perform UDP port scan.

        Args:
            target: Target IP or hostname.
            ports: UDP ports to scan.

        Returns:
            MCPResult with UDP scan results.
        """
        return self.invoke("udp_scan", {"target": target, "ports": ports})
