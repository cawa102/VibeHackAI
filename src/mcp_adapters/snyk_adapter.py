"""
Snyk MCP Adapter for PentestAgent.

Provides interface to Snyk MCP for vulnerability scanning.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError, MCPToolType


class SnykAdapter(BaseMCPAdapter):
    """
    Adapter for Snyk MCP.

    Provides vulnerability scanning capabilities:
    - Dependency vulnerability scanning
    - Container vulnerability scanning
    - CVE lookup
    - Vulnerability details
    """

    # Supported operations
    OPERATIONS = [
        "scan_deps",        # Scan dependencies for vulnerabilities
        "scan_container",   # Scan container image
        "lookup_vuln",      # Lookup specific vulnerability
        "search_vulns",     # Search vulnerabilities by package
        "get_vuln_details", # Get vulnerability details
        "list_cves",        # List CVEs for a package/version
    ]

    def __init__(
        self,
        timeout_seconds: int = 120,
        max_retries: int = 2,
        mock_mode: bool = False,
    ):
        """
        Initialize Snyk adapter.

        Args:
            timeout_seconds: Timeout for operations.
            max_retries: Maximum retry attempts.
            mock_mode: If True, return mock data instead of calling MCP.
        """
        super().__init__(
            tool_type=MCPToolType.SNYK,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
        self.mock_mode = mock_mode

    def get_supported_operations(self) -> List[str]:
        """Get list of supported operations."""
        return self.OPERATIONS.copy()

    def _invoke_tool(
        self,
        operation: str,
        params: Dict[str, Any],
    ) -> MCPResult:
        """
        Invoke Snyk MCP tool.

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
        """Invoke Snyk via MCP - placeholder for actual integration."""
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
            "scan_deps": self._mock_scan_deps,
            "scan_container": self._mock_scan_container,
            "lookup_vuln": self._mock_lookup_vuln,
            "search_vulns": self._mock_search_vulns,
            "get_vuln_details": self._mock_get_vuln_details,
            "list_cves": self._mock_list_cves,
        }

        handler = mock_handlers.get(operation)
        if handler:
            return handler(params)

        raise MCPError(
            f"Mock not implemented for: {operation}",
            tool=self.tool_name,
            operation=operation,
        )

    def _mock_scan_deps(self, params: Dict[str, Any]) -> MCPResult:
        """Mock dependency scan response."""
        return MCPResult(
            tool=self.tool_name,
            operation="scan_deps",
            success=True,
            data={
                "vulnerabilities": [
                    {
                        "id": "SNYK-JS-LODASH-590103",
                        "title": "Prototype Pollution",
                        "severity": "high",
                        "cvss_score": 7.4,
                        "package": "lodash",
                        "version": "4.17.15",
                        "fixed_in": "4.17.21",
                        "cve": "CVE-2020-8203",
                    },
                    {
                        "id": "SNYK-JS-AXIOS-1038255",
                        "title": "Server-Side Request Forgery",
                        "severity": "high",
                        "cvss_score": 7.5,
                        "package": "axios",
                        "version": "0.21.0",
                        "fixed_in": "0.21.1",
                        "cve": "CVE-2021-3749",
                    },
                    {
                        "id": "SNYK-PYTHON-DJANGO-1076802",
                        "title": "SQL Injection",
                        "severity": "critical",
                        "cvss_score": 9.8,
                        "package": "django",
                        "version": "2.2.10",
                        "fixed_in": "2.2.18",
                        "cve": "CVE-2021-3281",
                    },
                ],
                "total_vulnerabilities": 3,
                "critical": 1,
                "high": 2,
                "medium": 0,
                "low": 0,
            },
            metadata={"source": "snyk", "scan_type": "dependencies"},
        )

    def _mock_scan_container(self, params: Dict[str, Any]) -> MCPResult:
        """Mock container scan response."""
        image = params.get("image", "nginx:latest")

        return MCPResult(
            tool=self.tool_name,
            operation="scan_container",
            success=True,
            data={
                "image": image,
                "vulnerabilities": [
                    {
                        "id": "SNYK-LINUX-OPENSSL-2807587",
                        "title": "Buffer Overflow",
                        "severity": "critical",
                        "cvss_score": 9.8,
                        "package": "openssl",
                        "version": "1.1.1k",
                        "fixed_in": "1.1.1l",
                        "cve": "CVE-2021-3711",
                    },
                ],
                "base_image": "debian:bullseye",
                "total_vulnerabilities": 1,
            },
            metadata={"source": "snyk", "scan_type": "container"},
        )

    def _mock_lookup_vuln(self, params: Dict[str, Any]) -> MCPResult:
        """Mock vulnerability lookup response."""
        vuln_id = params.get("vuln_id", "CVE-2021-44228")

        return MCPResult(
            tool=self.tool_name,
            operation="lookup_vuln",
            success=True,
            data={
                "id": vuln_id,
                "title": "Log4Shell - Remote Code Execution",
                "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "severity": "critical",
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "affected_packages": [
                    {"name": "log4j-core", "versions": ">=2.0-beta9 <2.15.0"},
                ],
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    "https://logging.apache.org/log4j/2.x/security.html",
                ],
                "exploit_available": True,
                "exploit_maturity": "high",
            },
            metadata={"source": "snyk", "operation": "lookup_vuln"},
        )

    def _mock_search_vulns(self, params: Dict[str, Any]) -> MCPResult:
        """Mock vulnerability search response."""
        package = params.get("package", "")
        version = params.get("version", "")

        return MCPResult(
            tool=self.tool_name,
            operation="search_vulns",
            success=True,
            data={
                "package": package,
                "version": version,
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-44228",
                        "title": "Log4Shell",
                        "severity": "critical",
                        "cvss_score": 10.0,
                    },
                    {
                        "id": "CVE-2021-45046",
                        "title": "Log4j DoS",
                        "severity": "high",
                        "cvss_score": 9.0,
                    },
                ],
                "total": 2,
            },
            metadata={"source": "snyk", "operation": "search_vulns"},
        )

    def _mock_get_vuln_details(self, params: Dict[str, Any]) -> MCPResult:
        """Mock vulnerability details response."""
        vuln_id = params.get("vuln_id", "")

        return MCPResult(
            tool=self.tool_name,
            operation="get_vuln_details",
            success=True,
            data={
                "id": vuln_id,
                "title": "Remote Code Execution",
                "description": "A vulnerability that allows remote code execution.",
                "severity": "critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cwe": ["CWE-502", "CWE-94"],
                "affected_versions": "< 2.15.0",
                "patched_versions": ">= 2.15.0",
                "published_date": "2021-12-10",
                "exploit_available": True,
                "exploit_details": {
                    "maturity": "high",
                    "poc_available": True,
                    "in_the_wild": True,
                },
                "remediation": {
                    "upgrade": "Upgrade to version 2.15.0 or later",
                    "workaround": "Set log4j2.formatMsgNoLookups=true",
                },
            },
            metadata={"source": "snyk", "operation": "get_vuln_details"},
        )

    def _mock_list_cves(self, params: Dict[str, Any]) -> MCPResult:
        """Mock CVE list response."""
        package = params.get("package", "")
        version = params.get("version", "")

        return MCPResult(
            tool=self.tool_name,
            operation="list_cves",
            success=True,
            data={
                "package": package,
                "version": version,
                "cves": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "severity": "critical",
                        "cvss_score": 10.0,
                        "title": "Log4Shell",
                    },
                    {
                        "cve_id": "CVE-2021-45046",
                        "severity": "high",
                        "cvss_score": 9.0,
                        "title": "Log4j DoS",
                    },
                    {
                        "cve_id": "CVE-2021-45105",
                        "severity": "high",
                        "cvss_score": 7.5,
                        "title": "Log4j Infinite Recursion",
                    },
                ],
                "total": 3,
            },
            metadata={"source": "snyk", "operation": "list_cves"},
        )

    # Convenience methods

    def scan_dependencies(
        self,
        manifest_path: Optional[str] = None,
        project_type: Optional[str] = None,
    ) -> MCPResult:
        """
        Scan dependencies for vulnerabilities.

        Args:
            manifest_path: Path to manifest file (package.json, requirements.txt, etc.)
            project_type: Project type (npm, pip, maven, etc.)

        Returns:
            MCPResult with vulnerability scan results.
        """
        params = {}
        if manifest_path:
            params["manifest_path"] = manifest_path
        if project_type:
            params["project_type"] = project_type
        return self.invoke("scan_deps", params)

    def scan_container(self, image: str) -> MCPResult:
        """
        Scan container image for vulnerabilities.

        Args:
            image: Container image name (e.g., nginx:latest)

        Returns:
            MCPResult with vulnerability scan results.
        """
        return self.invoke("scan_container", {"image": image})

    def lookup_vulnerability(self, vuln_id: str) -> MCPResult:
        """
        Lookup specific vulnerability by ID.

        Args:
            vuln_id: Vulnerability ID (CVE or Snyk ID)

        Returns:
            MCPResult with vulnerability details.
        """
        return self.invoke("lookup_vuln", {"vuln_id": vuln_id})

    def search_vulnerabilities(
        self,
        package: str,
        version: Optional[str] = None,
    ) -> MCPResult:
        """
        Search vulnerabilities for a package.

        Args:
            package: Package name
            version: Optional version to filter

        Returns:
            MCPResult with matching vulnerabilities.
        """
        params = {"package": package}
        if version:
            params["version"] = version
        return self.invoke("search_vulns", params)

    def get_vulnerability_details(self, vuln_id: str) -> MCPResult:
        """
        Get detailed information about a vulnerability.

        Args:
            vuln_id: Vulnerability ID

        Returns:
            MCPResult with detailed vulnerability information.
        """
        return self.invoke("get_vuln_details", {"vuln_id": vuln_id})

    def list_cves_for_package(
        self,
        package: str,
        version: Optional[str] = None,
    ) -> MCPResult:
        """
        List CVEs affecting a package.

        Args:
            package: Package name
            version: Optional version

        Returns:
            MCPResult with CVE list.
        """
        params = {"package": package}
        if version:
            params["version"] = version
        return self.invoke("list_cves", params)
