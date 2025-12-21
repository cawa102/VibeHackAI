"""
Burpsuite MCP Adapter for PentestAgent.

Provides interface to Burpsuite MCP for web application enumeration.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError, MCPToolType


class BurpAdapter(BaseMCPAdapter):
    """
    Adapter for Burpsuite MCP.

    Provides web application enumeration capabilities:
    - Site map collection
    - Request/response capture
    - Form detection
    - API endpoint discovery
    """

    # Supported operations
    OPERATIONS = [
        "get_sitemap",       # Get site map for target
        "spider",            # Spider/crawl target
        "get_requests",      # Get captured requests
        "get_responses",     # Get captured responses
        "scan_passive",      # Passive scanning
        "get_forms",         # Get detected forms
        "get_endpoints",     # Get API endpoints
        "get_parameters",    # Get parameters from requests
        "get_cookies",       # Get cookies
        "get_headers",       # Get headers
    ]

    # Default spider settings
    SPIDER_SETTINGS = {
        "max_depth": 3,
        "max_pages": 100,
        "respect_robots": True,
        "follow_redirects": True,
        "crawl_forms": True,
    }

    def __init__(
        self,
        timeout_seconds: int = 300,  # 5 minutes for crawling
        max_retries: int = 1,
        mock_mode: bool = False,
        max_depth: int = 3,
    ):
        """
        Initialize Burp adapter.

        Args:
            timeout_seconds: Timeout for operations.
            max_retries: Maximum retry attempts.
            mock_mode: If True, return mock data instead of calling MCP.
            max_depth: Maximum crawl depth.
        """
        super().__init__(
            tool_type=MCPToolType.BURP,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
        self.mock_mode = mock_mode
        self.max_depth = max_depth

    def get_supported_operations(self) -> List[str]:
        """Get list of supported operations."""
        return self.OPERATIONS.copy()

    def _invoke_tool(
        self,
        operation: str,
        params: Dict[str, Any],
    ) -> MCPResult:
        """
        Invoke Burpsuite MCP tool.

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
        Invoke Burpsuite via MCP.

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
            "get_sitemap": self._mock_get_sitemap,
            "spider": self._mock_spider,
            "get_requests": self._mock_get_requests,
            "get_responses": self._mock_get_responses,
            "scan_passive": self._mock_scan_passive,
            "get_forms": self._mock_get_forms,
            "get_endpoints": self._mock_get_endpoints,
            "get_parameters": self._mock_get_parameters,
            "get_cookies": self._mock_get_cookies,
            "get_headers": self._mock_get_headers,
        }

        handler = mock_handlers.get(operation)
        if handler:
            return handler(params)

        raise MCPError(
            f"Mock not implemented for: {operation}",
            tool=self.tool_name,
            operation=operation,
        )

    def _mock_get_sitemap(self, params: Dict[str, Any]) -> MCPResult:
        """Mock sitemap response."""
        target = params.get("target", "https://example.com")
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        return MCPResult(
            tool=self.tool_name,
            operation="get_sitemap",
            success=True,
            data={
                "target": target,
                "base_url": base_url,
                "pages": [
                    {"url": f"{base_url}/", "method": "GET", "status": 200},
                    {"url": f"{base_url}/login", "method": "GET", "status": 200},
                    {"url": f"{base_url}/api/v1/users", "method": "GET", "status": 200},
                    {"url": f"{base_url}/api/v1/products", "method": "GET", "status": 200},
                    {"url": f"{base_url}/dashboard", "method": "GET", "status": 302},
                    {"url": f"{base_url}/admin", "method": "GET", "status": 403},
                    {"url": f"{base_url}/search", "method": "GET", "status": 200},
                    {"url": f"{base_url}/contact", "method": "GET", "status": 200},
                ],
                "total_pages": 8,
                "crawl_depth": 2,
            },
            metadata={"source": "burp", "operation": "get_sitemap"},
        )

    def _mock_spider(self, params: Dict[str, Any]) -> MCPResult:
        """Mock spider response."""
        target = params.get("target", "https://example.com")
        max_depth = params.get("max_depth", self.max_depth)

        return MCPResult(
            tool=self.tool_name,
            operation="spider",
            success=True,
            data={
                "target": target,
                "pages_crawled": 25,
                "forms_found": 4,
                "links_found": 45,
                "max_depth_reached": max_depth,
                "time_elapsed": "15.3s",
                "status": "completed",
            },
            metadata={"source": "burp", "operation": "spider"},
        )

    def _mock_get_requests(self, params: Dict[str, Any]) -> MCPResult:
        """Mock get requests response."""
        target = params.get("target", "https://example.com")
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        return MCPResult(
            tool=self.tool_name,
            operation="get_requests",
            success=True,
            data={
                "target": target,
                "requests": [
                    {
                        "id": "req-001",
                        "method": "GET",
                        "url": f"{base_url}/",
                        "headers": {
                            "Host": parsed.netloc,
                            "User-Agent": "Mozilla/5.0",
                            "Accept": "text/html",
                        },
                        "body": None,
                    },
                    {
                        "id": "req-002",
                        "method": "POST",
                        "url": f"{base_url}/login",
                        "headers": {
                            "Host": parsed.netloc,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        "body": "username=test&password=test",
                    },
                    {
                        "id": "req-003",
                        "method": "GET",
                        "url": f"{base_url}/api/v1/users?page=1&limit=10",
                        "headers": {
                            "Host": parsed.netloc,
                            "Authorization": "Bearer token123",
                            "Accept": "application/json",
                        },
                        "body": None,
                    },
                    {
                        "id": "req-004",
                        "method": "POST",
                        "url": f"{base_url}/api/v1/upload",
                        "headers": {
                            "Host": parsed.netloc,
                            "Content-Type": "multipart/form-data",
                        },
                        "body": "[binary data]",
                    },
                ],
                "total_requests": 4,
            },
            metadata={"source": "burp", "operation": "get_requests"},
        )

    def _mock_get_responses(self, params: Dict[str, Any]) -> MCPResult:
        """Mock get responses response."""
        target = params.get("target", "https://example.com")

        return MCPResult(
            tool=self.tool_name,
            operation="get_responses",
            success=True,
            data={
                "target": target,
                "responses": [
                    {
                        "request_id": "req-001",
                        "status": 200,
                        "headers": {
                            "Content-Type": "text/html",
                            "Server": "nginx/1.18.0",
                            "Set-Cookie": "session=abc123; HttpOnly",
                        },
                        "body_preview": "<!DOCTYPE html><html>...",
                        "body_length": 4523,
                    },
                    {
                        "request_id": "req-002",
                        "status": 302,
                        "headers": {
                            "Location": "/dashboard",
                            "Set-Cookie": "auth=xyz789; HttpOnly; Secure",
                        },
                        "body_preview": "",
                        "body_length": 0,
                    },
                    {
                        "request_id": "req-003",
                        "status": 200,
                        "headers": {
                            "Content-Type": "application/json",
                        },
                        "body_preview": '{"users": [...]}',
                        "body_length": 1250,
                    },
                ],
                "total_responses": 3,
            },
            metadata={"source": "burp", "operation": "get_responses"},
        )

    def _mock_scan_passive(self, params: Dict[str, Any]) -> MCPResult:
        """Mock passive scan response."""
        target = params.get("target", "https://example.com")

        return MCPResult(
            tool=self.tool_name,
            operation="scan_passive",
            success=True,
            data={
                "target": target,
                "issues": [
                    {
                        "type": "information_disclosure",
                        "severity": "low",
                        "url": f"{target}/api/v1/users",
                        "detail": "Server version disclosed in headers",
                    },
                    {
                        "type": "missing_security_header",
                        "severity": "info",
                        "url": target,
                        "detail": "X-Frame-Options header not set",
                    },
                    {
                        "type": "cookie_without_secure",
                        "severity": "low",
                        "url": f"{target}/login",
                        "detail": "Session cookie without Secure flag",
                    },
                ],
                "total_issues": 3,
            },
            metadata={"source": "burp", "operation": "scan_passive"},
        )

    def _mock_get_forms(self, params: Dict[str, Any]) -> MCPResult:
        """Mock get forms response."""
        target = params.get("target", "https://example.com")
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        return MCPResult(
            tool=self.tool_name,
            operation="get_forms",
            success=True,
            data={
                "target": target,
                "forms": [
                    {
                        "id": "form-001",
                        "url": f"{base_url}/login",
                        "method": "POST",
                        "action": "/login",
                        "enctype": "application/x-www-form-urlencoded",
                        "fields": [
                            {"name": "username", "type": "text", "required": True},
                            {"name": "password", "type": "password", "required": True},
                            {"name": "remember", "type": "checkbox", "required": False},
                            {"name": "csrf_token", "type": "hidden", "required": True},
                        ],
                        "is_login_form": True,
                    },
                    {
                        "id": "form-002",
                        "url": f"{base_url}/search",
                        "method": "GET",
                        "action": "/search",
                        "enctype": "application/x-www-form-urlencoded",
                        "fields": [
                            {"name": "q", "type": "text", "required": True},
                            {"name": "category", "type": "select", "required": False},
                        ],
                        "is_login_form": False,
                    },
                    {
                        "id": "form-003",
                        "url": f"{base_url}/contact",
                        "method": "POST",
                        "action": "/contact",
                        "enctype": "application/x-www-form-urlencoded",
                        "fields": [
                            {"name": "name", "type": "text", "required": True},
                            {"name": "email", "type": "email", "required": True},
                            {"name": "message", "type": "textarea", "required": True},
                        ],
                        "is_login_form": False,
                    },
                    {
                        "id": "form-004",
                        "url": f"{base_url}/upload",
                        "method": "POST",
                        "action": "/api/v1/upload",
                        "enctype": "multipart/form-data",
                        "fields": [
                            {"name": "file", "type": "file", "required": True},
                            {"name": "description", "type": "text", "required": False},
                        ],
                        "is_login_form": False,
                        "has_file_upload": True,
                    },
                ],
                "total_forms": 4,
                "login_forms": 1,
                "file_upload_forms": 1,
            },
            metadata={"source": "burp", "operation": "get_forms"},
        )

    def _mock_get_endpoints(self, params: Dict[str, Any]) -> MCPResult:
        """Mock get endpoints response."""
        target = params.get("target", "https://example.com")
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        return MCPResult(
            tool=self.tool_name,
            operation="get_endpoints",
            success=True,
            data={
                "target": target,
                "endpoints": [
                    {
                        "path": "/api/v1/users",
                        "methods": ["GET", "POST"],
                        "content_type": "application/json",
                        "auth_required": True,
                        "parameters": [
                            {"name": "page", "location": "query", "type": "integer"},
                            {"name": "limit", "location": "query", "type": "integer"},
                        ],
                    },
                    {
                        "path": "/api/v1/users/{id}",
                        "methods": ["GET", "PUT", "DELETE"],
                        "content_type": "application/json",
                        "auth_required": True,
                        "parameters": [
                            {"name": "id", "location": "path", "type": "integer"},
                        ],
                    },
                    {
                        "path": "/api/v1/products",
                        "methods": ["GET"],
                        "content_type": "application/json",
                        "auth_required": False,
                        "parameters": [
                            {"name": "category", "location": "query", "type": "string"},
                            {"name": "sort", "location": "query", "type": "string"},
                        ],
                    },
                    {
                        "path": "/api/v1/upload",
                        "methods": ["POST"],
                        "content_type": "multipart/form-data",
                        "auth_required": True,
                        "parameters": [
                            {"name": "file", "location": "body", "type": "file"},
                        ],
                    },
                    {
                        "path": "/api/v1/auth/login",
                        "methods": ["POST"],
                        "content_type": "application/json",
                        "auth_required": False,
                        "parameters": [
                            {"name": "username", "location": "body", "type": "string"},
                            {"name": "password", "location": "body", "type": "string"},
                        ],
                    },
                ],
                "total_endpoints": 5,
                "authenticated_endpoints": 3,
                "public_endpoints": 2,
            },
            metadata={"source": "burp", "operation": "get_endpoints"},
        )

    def _mock_get_parameters(self, params: Dict[str, Any]) -> MCPResult:
        """Mock get parameters response."""
        target = params.get("target", "https://example.com")

        return MCPResult(
            tool=self.tool_name,
            operation="get_parameters",
            success=True,
            data={
                "target": target,
                "parameters": [
                    {"name": "username", "type": "string", "locations": ["body"], "endpoints": ["/login", "/api/v1/auth/login"]},
                    {"name": "password", "type": "string", "locations": ["body"], "endpoints": ["/login", "/api/v1/auth/login"]},
                    {"name": "q", "type": "string", "locations": ["query"], "endpoints": ["/search"]},
                    {"name": "page", "type": "integer", "locations": ["query"], "endpoints": ["/api/v1/users", "/api/v1/products"]},
                    {"name": "limit", "type": "integer", "locations": ["query"], "endpoints": ["/api/v1/users"]},
                    {"name": "id", "type": "integer", "locations": ["path"], "endpoints": ["/api/v1/users/{id}"]},
                    {"name": "category", "type": "string", "locations": ["query"], "endpoints": ["/api/v1/products"]},
                    {"name": "file", "type": "file", "locations": ["body"], "endpoints": ["/api/v1/upload"]},
                    {"name": "csrf_token", "type": "string", "locations": ["body"], "endpoints": ["/login", "/contact"]},
                ],
                "total_parameters": 9,
                "file_parameters": 1,
                "auth_parameters": 2,
            },
            metadata={"source": "burp", "operation": "get_parameters"},
        )

    def _mock_get_cookies(self, params: Dict[str, Any]) -> MCPResult:
        """Mock get cookies response."""
        target = params.get("target", "https://example.com")

        return MCPResult(
            tool=self.tool_name,
            operation="get_cookies",
            success=True,
            data={
                "target": target,
                "cookies": [
                    {
                        "name": "session",
                        "value": "[redacted]",
                        "domain": "example.com",
                        "path": "/",
                        "httponly": True,
                        "secure": True,
                        "samesite": "Lax",
                    },
                    {
                        "name": "csrf_token",
                        "value": "[redacted]",
                        "domain": "example.com",
                        "path": "/",
                        "httponly": False,
                        "secure": True,
                        "samesite": "Strict",
                    },
                    {
                        "name": "preferences",
                        "value": "[redacted]",
                        "domain": "example.com",
                        "path": "/",
                        "httponly": False,
                        "secure": False,
                        "samesite": None,
                    },
                ],
                "total_cookies": 3,
                "session_cookies": 1,
            },
            metadata={"source": "burp", "operation": "get_cookies"},
        )

    def _mock_get_headers(self, params: Dict[str, Any]) -> MCPResult:
        """Mock get headers response."""
        target = params.get("target", "https://example.com")

        return MCPResult(
            tool=self.tool_name,
            operation="get_headers",
            success=True,
            data={
                "target": target,
                "response_headers": {
                    "Server": "nginx/1.18.0",
                    "X-Powered-By": "Express",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Frame-Options": None,
                    "X-Content-Type-Options": "nosniff",
                    "Strict-Transport-Security": "max-age=31536000",
                },
                "security_headers": {
                    "present": ["Content-Security-Policy", "X-Content-Type-Options", "Strict-Transport-Security"],
                    "missing": ["X-Frame-Options", "X-XSS-Protection"],
                },
            },
            metadata={"source": "burp", "operation": "get_headers"},
        )

    # Convenience methods

    def get_sitemap(self, target: str) -> MCPResult:
        """
        Get site map for target.

        Args:
            target: Target URL.

        Returns:
            MCPResult with site map.
        """
        return self.invoke("get_sitemap", {"target": target})

    def spider(
        self,
        target: str,
        max_depth: Optional[int] = None,
        max_pages: Optional[int] = None,
    ) -> MCPResult:
        """
        Spider/crawl target.

        Args:
            target: Target URL.
            max_depth: Maximum crawl depth.
            max_pages: Maximum pages to crawl.

        Returns:
            MCPResult with spider results.
        """
        params = {"target": target}
        if max_depth is not None:
            params["max_depth"] = max_depth
        if max_pages is not None:
            params["max_pages"] = max_pages
        return self.invoke("spider", params)

    def get_requests(self, target: str) -> MCPResult:
        """
        Get captured requests for target.

        Args:
            target: Target URL.

        Returns:
            MCPResult with requests.
        """
        return self.invoke("get_requests", {"target": target})

    def get_responses(self, target: str) -> MCPResult:
        """
        Get captured responses for target.

        Args:
            target: Target URL.

        Returns:
            MCPResult with responses.
        """
        return self.invoke("get_responses", {"target": target})

    def scan_passive(self, target: str) -> MCPResult:
        """
        Run passive scan on target.

        Args:
            target: Target URL.

        Returns:
            MCPResult with passive scan results.
        """
        return self.invoke("scan_passive", {"target": target})

    def get_forms(self, target: str) -> MCPResult:
        """
        Get detected forms from target.

        Args:
            target: Target URL.

        Returns:
            MCPResult with forms.
        """
        return self.invoke("get_forms", {"target": target})

    def get_endpoints(self, target: str) -> MCPResult:
        """
        Get API endpoints from target.

        Args:
            target: Target URL.

        Returns:
            MCPResult with endpoints.
        """
        return self.invoke("get_endpoints", {"target": target})

    def get_parameters(self, target: str) -> MCPResult:
        """
        Get parameters from target.

        Args:
            target: Target URL.

        Returns:
            MCPResult with parameters.
        """
        return self.invoke("get_parameters", {"target": target})

    def get_cookies(self, target: str) -> MCPResult:
        """
        Get cookies from target.

        Args:
            target: Target URL.

        Returns:
            MCPResult with cookies.
        """
        return self.invoke("get_cookies", {"target": target})

    def get_headers(self, target: str) -> MCPResult:
        """
        Get response headers from target.

        Args:
            target: Target URL.

        Returns:
            MCPResult with headers.
        """
        return self.invoke("get_headers", {"target": target})
