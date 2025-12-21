"""
OSINT MCP Adapter for PentestAgent.

Provides interface to OSINT tools for passive reconnaissance.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError, MCPToolType


class OSINTAdapter(BaseMCPAdapter):
    """
    Adapter for OSINT MCP.

    Provides open-source intelligence capabilities:
    - DNS enumeration
    - WHOIS lookups
    - Subdomain discovery
    - Email harvesting
    - Technology detection
    """

    # Supported operations
    OPERATIONS = [
        "dns_lookup",       # DNS record lookup
        "whois",            # WHOIS information
        "subdomains",       # Subdomain enumeration
        "mx_records",       # Mail server records
        "ns_records",       # Nameserver records
        "txt_records",      # TXT records (SPF, DKIM, etc.)
        "cert_search",      # Certificate transparency search
        "email_harvest",    # Email harvesting (public sources)
        "tech_detect",      # Technology detection
    ]

    def __init__(
        self,
        timeout_seconds: int = 30,
        max_retries: int = 2,
        mock_mode: bool = False,
    ):
        """
        Initialize OSINT adapter.

        Args:
            timeout_seconds: Timeout for operations.
            max_retries: Maximum retry attempts.
            mock_mode: If True, return mock data instead of calling MCP.
        """
        super().__init__(
            tool_type=MCPToolType.OSINT,
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
        Invoke OSINT MCP tool.

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
        Invoke OSINT via MCP.

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
            "dns_lookup": self._mock_dns_lookup,
            "whois": self._mock_whois,
            "subdomains": self._mock_subdomains,
            "mx_records": self._mock_mx_records,
            "ns_records": self._mock_ns_records,
            "txt_records": self._mock_txt_records,
            "cert_search": self._mock_cert_search,
            "email_harvest": self._mock_email_harvest,
            "tech_detect": self._mock_tech_detect,
        }

        handler = mock_handlers.get(operation)
        if handler:
            return handler(params)

        raise MCPError(
            f"Mock not implemented for: {operation}",
            tool=self.tool_name,
            operation=operation,
        )

    def _mock_dns_lookup(self, params: Dict[str, Any]) -> MCPResult:
        """Mock DNS lookup response."""
        domain = params.get("domain", "example.com")
        record_type = params.get("type", "A")

        records = {
            "A": ["192.168.1.1", "192.168.1.2"],
            "AAAA": ["2001:db8::1"],
            "CNAME": ["cdn.example.com"],
            "MX": ["mail.example.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 include:_spf.example.com ~all"],
        }

        return MCPResult(
            tool=self.tool_name,
            operation="dns_lookup",
            success=True,
            data={
                "domain": domain,
                "type": record_type,
                "records": records.get(record_type, []),
            },
            metadata={"source": "osint"},
        )

    def _mock_whois(self, params: Dict[str, Any]) -> MCPResult:
        """Mock WHOIS response."""
        domain = params.get("domain", "example.com")
        return MCPResult(
            tool=self.tool_name,
            operation="whois",
            success=True,
            data={
                "domain": domain,
                "registrar": "Example Registrar, Inc.",
                "creation_date": "2000-01-01",
                "expiration_date": "2025-01-01",
                "updated_date": "2024-01-01",
                "name_servers": ["ns1.example.com", "ns2.example.com"],
                "registrant": {
                    "organization": "Example Organization",
                    "country": "US",
                    "state": "California",
                },
                "admin_contact": {
                    "email": "admin@example.com",
                },
                "tech_contact": {
                    "email": "tech@example.com",
                },
            },
            metadata={"source": "whois"},
        )

    def _mock_subdomains(self, params: Dict[str, Any]) -> MCPResult:
        """Mock subdomain enumeration response."""
        domain = params.get("domain", "example.com")
        return MCPResult(
            tool=self.tool_name,
            operation="subdomains",
            success=True,
            data={
                "domain": domain,
                "subdomains": [
                    f"www.{domain}",
                    f"mail.{domain}",
                    f"api.{domain}",
                    f"admin.{domain}",
                    f"dev.{domain}",
                    f"staging.{domain}",
                    f"cdn.{domain}",
                ],
            },
            metadata={"source": "osint", "methods": ["crt.sh", "dns_brute"]},
        )

    def _mock_mx_records(self, params: Dict[str, Any]) -> MCPResult:
        """Mock MX records response."""
        domain = params.get("domain", "example.com")
        return MCPResult(
            tool=self.tool_name,
            operation="mx_records",
            success=True,
            data={
                "domain": domain,
                "mx_records": [
                    {"priority": 10, "host": f"mx1.{domain}"},
                    {"priority": 20, "host": f"mx2.{domain}"},
                ],
            },
            metadata={"source": "dns"},
        )

    def _mock_ns_records(self, params: Dict[str, Any]) -> MCPResult:
        """Mock NS records response."""
        domain = params.get("domain", "example.com")
        return MCPResult(
            tool=self.tool_name,
            operation="ns_records",
            success=True,
            data={
                "domain": domain,
                "ns_records": [f"ns1.{domain}", f"ns2.{domain}"],
            },
            metadata={"source": "dns"},
        )

    def _mock_txt_records(self, params: Dict[str, Any]) -> MCPResult:
        """Mock TXT records response."""
        domain = params.get("domain", "example.com")
        return MCPResult(
            tool=self.tool_name,
            operation="txt_records",
            success=True,
            data={
                "domain": domain,
                "txt_records": [
                    "v=spf1 include:_spf.google.com ~all",
                    "google-site-verification=xxxxx",
                    "MS=ms12345678",
                ],
            },
            metadata={"source": "dns"},
        )

    def _mock_cert_search(self, params: Dict[str, Any]) -> MCPResult:
        """Mock certificate transparency search response."""
        domain = params.get("domain", "example.com")
        return MCPResult(
            tool=self.tool_name,
            operation="cert_search",
            success=True,
            data={
                "domain": domain,
                "certificates": [
                    {
                        "common_name": domain,
                        "issuer": "Let's Encrypt Authority X3",
                        "not_before": "2024-01-01",
                        "not_after": "2024-04-01",
                        "san": [domain, f"www.{domain}"],
                    },
                    {
                        "common_name": f"*.{domain}",
                        "issuer": "DigiCert Inc",
                        "not_before": "2024-01-01",
                        "not_after": "2025-01-01",
                        "san": [f"*.{domain}"],
                    },
                ],
            },
            metadata={"source": "crt.sh"},
        )

    def _mock_email_harvest(self, params: Dict[str, Any]) -> MCPResult:
        """Mock email harvesting response."""
        domain = params.get("domain", "example.com")
        return MCPResult(
            tool=self.tool_name,
            operation="email_harvest",
            success=True,
            data={
                "domain": domain,
                "emails": [
                    f"admin@{domain}",
                    f"info@{domain}",
                    f"support@{domain}",
                    f"contact@{domain}",
                ],
                "patterns": [
                    "{first}.{last}@{domain}",
                    "{first}{last}@{domain}",
                ],
            },
            metadata={"source": "osint", "methods": ["google", "linkedin"]},
        )

    def _mock_tech_detect(self, params: Dict[str, Any]) -> MCPResult:
        """Mock technology detection response."""
        target = params.get("target", "example.com")
        return MCPResult(
            tool=self.tool_name,
            operation="tech_detect",
            success=True,
            data={
                "target": target,
                "technologies": {
                    "web_servers": ["nginx/1.18.0"],
                    "programming_languages": ["PHP", "JavaScript"],
                    "frameworks": ["Laravel", "React"],
                    "cms": ["WordPress 6.0"],
                    "cdn": ["Cloudflare"],
                    "analytics": ["Google Analytics"],
                    "security": ["ModSecurity", "Cloudflare WAF"],
                },
            },
            metadata={"source": "wappalyzer"},
        )

    # Convenience methods

    def dns_lookup(
        self,
        domain: str,
        record_type: str = "A",
    ) -> MCPResult:
        """
        Look up DNS records.

        Args:
            domain: Domain to look up.
            record_type: Type of record (A, AAAA, MX, etc.).

        Returns:
            MCPResult with DNS records.
        """
        return self.invoke("dns_lookup", {"domain": domain, "type": record_type})

    def whois(self, domain: str) -> MCPResult:
        """
        Get WHOIS information.

        Args:
            domain: Domain to look up.

        Returns:
            MCPResult with WHOIS data.
        """
        return self.invoke("whois", {"domain": domain})

    def enumerate_subdomains(self, domain: str) -> MCPResult:
        """
        Enumerate subdomains.

        Args:
            domain: Domain to enumerate.

        Returns:
            MCPResult with subdomains.
        """
        return self.invoke("subdomains", {"domain": domain})

    def get_mx_records(self, domain: str) -> MCPResult:
        """
        Get MX records.

        Args:
            domain: Domain to look up.

        Returns:
            MCPResult with MX records.
        """
        return self.invoke("mx_records", {"domain": domain})

    def get_ns_records(self, domain: str) -> MCPResult:
        """
        Get NS records.

        Args:
            domain: Domain to look up.

        Returns:
            MCPResult with NS records.
        """
        return self.invoke("ns_records", {"domain": domain})

    def get_txt_records(self, domain: str) -> MCPResult:
        """
        Get TXT records.

        Args:
            domain: Domain to look up.

        Returns:
            MCPResult with TXT records.
        """
        return self.invoke("txt_records", {"domain": domain})

    def search_certificates(self, domain: str) -> MCPResult:
        """
        Search certificate transparency logs.

        Args:
            domain: Domain to search.

        Returns:
            MCPResult with certificates.
        """
        return self.invoke("cert_search", {"domain": domain})

    def harvest_emails(self, domain: str) -> MCPResult:
        """
        Harvest emails from public sources.

        Args:
            domain: Domain to search.

        Returns:
            MCPResult with emails.
        """
        return self.invoke("email_harvest", {"domain": domain})

    def detect_technologies(self, target: str) -> MCPResult:
        """
        Detect technologies used by target.

        Args:
            target: Target URL or domain.

        Returns:
            MCPResult with technologies.
        """
        return self.invoke("tech_detect", {"target": target})
