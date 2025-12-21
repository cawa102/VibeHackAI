"""
CVE Research MCP Adapter for PentestAgent.

Provides interface to CVE Research MCP for vulnerability lookup.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError, MCPToolType


class CVEAdapter(BaseMCPAdapter):
    """
    Adapter for CVE Research MCP.

    Provides CVE lookup and vulnerability research:
    - CVE search by ID
    - CVE search by product/vendor
    - CVSS scoring details
    - Exploit availability check
    """

    # Supported operations
    OPERATIONS = [
        "lookup_cve",           # Lookup CVE by ID
        "search_by_product",    # Search CVEs by product name
        "search_by_vendor",     # Search CVEs by vendor
        "search_by_keyword",    # Keyword search
        "get_cve_details",      # Get detailed CVE info
        "get_exploit_info",     # Get exploit availability info
        "search_recent",        # Search recent CVEs
    ]

    def __init__(
        self,
        timeout_seconds: int = 60,
        max_retries: int = 2,
        mock_mode: bool = False,
    ):
        """
        Initialize CVE adapter.

        Args:
            timeout_seconds: Timeout for operations.
            max_retries: Maximum retry attempts.
            mock_mode: If True, return mock data instead of calling MCP.
        """
        # Use SNYK as a workaround since we can't add new enum values easily
        # In real implementation, would use a proper CVE tool type
        super().__init__(
            tool_type=MCPToolType.SNYK,  # Placeholder
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
        self.mock_mode = mock_mode
        self._tool_name = "cve_research"

    @property
    def tool_name(self) -> str:
        """Override tool name."""
        return self._tool_name

    def get_supported_operations(self) -> List[str]:
        """Get list of supported operations."""
        return self.OPERATIONS.copy()

    def _invoke_tool(
        self,
        operation: str,
        params: Dict[str, Any],
    ) -> MCPResult:
        """
        Invoke CVE Research MCP tool.

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
        """Invoke CVE Research via MCP - placeholder."""
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
            "lookup_cve": self._mock_lookup_cve,
            "search_by_product": self._mock_search_by_product,
            "search_by_vendor": self._mock_search_by_vendor,
            "search_by_keyword": self._mock_search_by_keyword,
            "get_cve_details": self._mock_get_cve_details,
            "get_exploit_info": self._mock_get_exploit_info,
            "search_recent": self._mock_search_recent,
        }

        handler = mock_handlers.get(operation)
        if handler:
            return handler(params)

        raise MCPError(
            f"Mock not implemented for: {operation}",
            tool=self.tool_name,
            operation=operation,
        )

    def _mock_lookup_cve(self, params: Dict[str, Any]) -> MCPResult:
        """Mock CVE lookup response."""
        cve_id = params.get("cve_id", "CVE-2021-44228")

        return MCPResult(
            tool=self.tool_name,
            operation="lookup_cve",
            success=True,
            data={
                "cve_id": cve_id,
                "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "published": "2021-12-10",
                "modified": "2023-04-03",
                "cvss_v3": {
                    "score": 10.0,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "severity": "CRITICAL",
                },
                "cvss_v2": {
                    "score": 9.3,
                    "vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                },
                "cwe": ["CWE-917", "CWE-502", "CWE-400", "CWE-20"],
                "references": [
                    {"url": "https://logging.apache.org/log4j/2.x/security.html", "source": "CONFIRM"},
                    {"url": "https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance", "source": "US-CERT"},
                ],
                "affected_products": [
                    {"vendor": "apache", "product": "log4j", "versions": "2.0-beta9 to 2.14.1"},
                ],
            },
            metadata={"source": "cve_research", "operation": "lookup_cve"},
        )

    def _mock_search_by_product(self, params: Dict[str, Any]) -> MCPResult:
        """Mock product search response."""
        product = params.get("product", "")
        version = params.get("version", "")

        return MCPResult(
            tool=self.tool_name,
            operation="search_by_product",
            success=True,
            data={
                "product": product,
                "version": version,
                "cves": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "severity": "CRITICAL",
                        "cvss_score": 10.0,
                        "title": "Log4Shell - Remote Code Execution",
                        "published": "2021-12-10",
                    },
                    {
                        "cve_id": "CVE-2021-45046",
                        "severity": "CRITICAL",
                        "cvss_score": 9.0,
                        "title": "Log4j - Context Lookup DoS",
                        "published": "2021-12-14",
                    },
                    {
                        "cve_id": "CVE-2021-45105",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "title": "Log4j - Infinite Recursion",
                        "published": "2021-12-18",
                    },
                ],
                "total": 3,
            },
            metadata={"source": "cve_research", "operation": "search_by_product"},
        )

    def _mock_search_by_vendor(self, params: Dict[str, Any]) -> MCPResult:
        """Mock vendor search response."""
        vendor = params.get("vendor", "")

        return MCPResult(
            tool=self.tool_name,
            operation="search_by_vendor",
            success=True,
            data={
                "vendor": vendor,
                "cves": [
                    {
                        "cve_id": "CVE-2023-44487",
                        "product": "http2",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "title": "HTTP/2 Rapid Reset Attack",
                    },
                    {
                        "cve_id": "CVE-2023-25690",
                        "product": "http_server",
                        "severity": "CRITICAL",
                        "cvss_score": 9.8,
                        "title": "HTTP Request Splitting",
                    },
                ],
                "total": 2,
            },
            metadata={"source": "cve_research", "operation": "search_by_vendor"},
        )

    def _mock_search_by_keyword(self, params: Dict[str, Any]) -> MCPResult:
        """Mock keyword search response."""
        keyword = params.get("keyword", "")

        return MCPResult(
            tool=self.tool_name,
            operation="search_by_keyword",
            success=True,
            data={
                "keyword": keyword,
                "cves": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "severity": "CRITICAL",
                        "cvss_score": 10.0,
                        "title": "Log4Shell",
                        "published": "2021-12-10",
                    },
                ],
                "total": 1,
            },
            metadata={"source": "cve_research", "operation": "search_by_keyword"},
        )

    def _mock_get_cve_details(self, params: Dict[str, Any]) -> MCPResult:
        """Mock CVE details response."""
        cve_id = params.get("cve_id", "")

        return MCPResult(
            tool=self.tool_name,
            operation="get_cve_details",
            success=True,
            data={
                "cve_id": cve_id,
                "title": "Remote Code Execution via JNDI Injection",
                "description": "A remote code execution vulnerability exists in Apache Log4j.",
                "severity": "CRITICAL",
                "cvss_v3": {
                    "score": 10.0,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    "attack_vector": "NETWORK",
                    "attack_complexity": "LOW",
                    "privileges_required": "NONE",
                    "user_interaction": "NONE",
                    "scope": "CHANGED",
                    "confidentiality_impact": "HIGH",
                    "integrity_impact": "HIGH",
                    "availability_impact": "HIGH",
                },
                "cwe": [
                    {"id": "CWE-917", "name": "Expression Language Injection"},
                    {"id": "CWE-502", "name": "Deserialization of Untrusted Data"},
                ],
                "affected_configurations": [
                    {
                        "vendor": "apache",
                        "product": "log4j",
                        "version_start": "2.0-beta9",
                        "version_end": "2.14.1",
                        "vulnerable": True,
                    },
                ],
                "remediation": {
                    "recommended_action": "Upgrade to Log4j 2.17.0 or later",
                    "workarounds": [
                        "Set log4j2.formatMsgNoLookups=true",
                        "Remove JndiLookup class from classpath",
                    ],
                },
                "exploit_info": {
                    "public_exploits": True,
                    "exploit_db_id": "50592",
                    "metasploit_module": "exploit/multi/http/log4shell_header_injection",
                },
            },
            metadata={"source": "cve_research", "operation": "get_cve_details"},
        )

    def _mock_get_exploit_info(self, params: Dict[str, Any]) -> MCPResult:
        """Mock exploit info response."""
        cve_id = params.get("cve_id", "")

        return MCPResult(
            tool=self.tool_name,
            operation="get_exploit_info",
            success=True,
            data={
                "cve_id": cve_id,
                "exploit_available": True,
                "exploit_maturity": "functional",
                "exploits": [
                    {
                        "source": "exploit-db",
                        "id": "50592",
                        "title": "Apache Log4j 2 - Remote Code Execution",
                        "type": "remote",
                        "platform": "multiple",
                        "verified": True,
                        "url": "https://www.exploit-db.com/exploits/50592",
                    },
                    {
                        "source": "metasploit",
                        "module": "exploit/multi/http/log4shell_header_injection",
                        "rank": "excellent",
                        "verified": True,
                    },
                    {
                        "source": "github",
                        "repo": "kozmer/log4j-shell-poc",
                        "stars": 1500,
                        "last_updated": "2022-01-15",
                    },
                ],
                "in_the_wild": True,
                "ransomware_associated": True,
            },
            metadata={"source": "cve_research", "operation": "get_exploit_info"},
        )

    def _mock_search_recent(self, params: Dict[str, Any]) -> MCPResult:
        """Mock recent CVE search response."""
        days = params.get("days", 7)
        severity = params.get("severity", None)

        return MCPResult(
            tool=self.tool_name,
            operation="search_recent",
            success=True,
            data={
                "days": days,
                "severity_filter": severity,
                "cves": [
                    {
                        "cve_id": "CVE-2024-0001",
                        "severity": "CRITICAL",
                        "cvss_score": 9.8,
                        "title": "Example Critical Vulnerability",
                        "published": "2024-01-15",
                    },
                    {
                        "cve_id": "CVE-2024-0002",
                        "severity": "HIGH",
                        "cvss_score": 8.5,
                        "title": "Example High Vulnerability",
                        "published": "2024-01-14",
                    },
                ],
                "total": 2,
            },
            metadata={"source": "cve_research", "operation": "search_recent"},
        )

    # Convenience methods

    def lookup_cve(self, cve_id: str) -> MCPResult:
        """
        Lookup CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            MCPResult with CVE information.
        """
        return self.invoke("lookup_cve", {"cve_id": cve_id})

    def search_by_product(
        self,
        product: str,
        version: Optional[str] = None,
        vendor: Optional[str] = None,
    ) -> MCPResult:
        """
        Search CVEs by product.

        Args:
            product: Product name
            version: Optional version
            vendor: Optional vendor name

        Returns:
            MCPResult with matching CVEs.
        """
        params = {"product": product}
        if version:
            params["version"] = version
        if vendor:
            params["vendor"] = vendor
        return self.invoke("search_by_product", params)

    def search_by_vendor(self, vendor: str) -> MCPResult:
        """
        Search CVEs by vendor.

        Args:
            vendor: Vendor name

        Returns:
            MCPResult with matching CVEs.
        """
        return self.invoke("search_by_vendor", {"vendor": vendor})

    def search_by_keyword(self, keyword: str) -> MCPResult:
        """
        Search CVEs by keyword.

        Args:
            keyword: Search keyword

        Returns:
            MCPResult with matching CVEs.
        """
        return self.invoke("search_by_keyword", {"keyword": keyword})

    def get_cve_details(self, cve_id: str) -> MCPResult:
        """
        Get detailed CVE information.

        Args:
            cve_id: CVE identifier

        Returns:
            MCPResult with detailed CVE info.
        """
        return self.invoke("get_cve_details", {"cve_id": cve_id})

    def get_exploit_info(self, cve_id: str) -> MCPResult:
        """
        Get exploit availability information for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            MCPResult with exploit information.
        """
        return self.invoke("get_exploit_info", {"cve_id": cve_id})

    def search_recent_cves(
        self,
        days: int = 7,
        severity: Optional[str] = None,
    ) -> MCPResult:
        """
        Search recent CVEs.

        Args:
            days: Number of days to look back
            severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            MCPResult with recent CVEs.
        """
        params = {"days": days}
        if severity:
            params["severity"] = severity
        return self.invoke("search_recent", params)
