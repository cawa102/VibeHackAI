"""
GitHub MCP Adapter for PentestAgent.

Provides interface to GitHub MCP for PoC/Exploit search.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError, MCPToolType


class GitHubAdapter(BaseMCPAdapter):
    """
    Adapter for GitHub MCP.

    Provides PoC/Exploit search capabilities:
    - Search repositories by CVE
    - Search exploit code
    - Get repository details
    - Evaluate PoC reliability
    """

    # Supported operations
    OPERATIONS = [
        "search_repos",         # Search repositories
        "search_code",          # Search code
        "search_pocs",          # Search PoC repositories
        "get_repo_info",        # Get repository information
        "get_repo_contents",    # Get repository file contents
        "search_exploits",      # Search for exploit code
        "evaluate_reliability", # Evaluate PoC reliability
    ]

    def __init__(
        self,
        timeout_seconds: int = 60,
        max_retries: int = 2,
        mock_mode: bool = False,
    ):
        """
        Initialize GitHub adapter.

        Args:
            timeout_seconds: Timeout for operations.
            max_retries: Maximum retry attempts.
            mock_mode: If True, return mock data instead of calling MCP.
        """
        super().__init__(
            tool_type=MCPToolType.GITHUB,
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
        Invoke GitHub MCP tool.

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
        """Invoke GitHub via MCP - placeholder."""
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
            "search_repos": self._mock_search_repos,
            "search_code": self._mock_search_code,
            "search_pocs": self._mock_search_pocs,
            "get_repo_info": self._mock_get_repo_info,
            "get_repo_contents": self._mock_get_repo_contents,
            "search_exploits": self._mock_search_exploits,
            "evaluate_reliability": self._mock_evaluate_reliability,
        }

        handler = mock_handlers.get(operation)
        if handler:
            return handler(params)

        raise MCPError(
            f"Mock not implemented for: {operation}",
            tool=self.tool_name,
            operation=operation,
        )

    def _mock_search_repos(self, params: Dict[str, Any]) -> MCPResult:
        """Mock repository search response."""
        query = params.get("query", "")

        return MCPResult(
            tool=self.tool_name,
            operation="search_repos",
            success=True,
            data={
                "query": query,
                "repositories": [
                    {
                        "full_name": "kozmer/log4j-shell-poc",
                        "description": "A Proof-Of-Concept for the CVE-2021-44228 vulnerability",
                        "url": "https://github.com/kozmer/log4j-shell-poc",
                        "stars": 1523,
                        "forks": 432,
                        "language": "Python",
                        "last_updated": "2022-01-15T10:30:00Z",
                        "topics": ["cve-2021-44228", "log4j", "poc", "exploit"],
                    },
                    {
                        "full_name": "jas502n/Log4j2-CVE-2021-44228",
                        "description": "Log4j2 Remote Code Execution",
                        "url": "https://github.com/jas502n/Log4j2-CVE-2021-44228",
                        "stars": 987,
                        "forks": 256,
                        "language": "Java",
                        "last_updated": "2022-02-10T08:15:00Z",
                        "topics": ["log4j2", "rce", "cve-2021-44228"],
                    },
                ],
                "total": 2,
            },
            metadata={"source": "github", "operation": "search_repos"},
        )

    def _mock_search_code(self, params: Dict[str, Any]) -> MCPResult:
        """Mock code search response."""
        query = params.get("query", "")

        return MCPResult(
            tool=self.tool_name,
            operation="search_code",
            success=True,
            data={
                "query": query,
                "code_results": [
                    {
                        "repository": "kozmer/log4j-shell-poc",
                        "path": "poc.py",
                        "url": "https://github.com/kozmer/log4j-shell-poc/blob/main/poc.py",
                        "snippet": "def exploit(target, callback):\n    payload = '${jndi:ldap://' + callback + '/a}'",
                    },
                    {
                        "repository": "jas502n/Log4j2-CVE-2021-44228",
                        "path": "Exploit.java",
                        "url": "https://github.com/jas502n/Log4j2-CVE-2021-44228/blob/main/Exploit.java",
                        "snippet": "public class Exploit {\n    static {\n        Runtime.getRuntime().exec(cmd);",
                    },
                ],
                "total": 2,
            },
            metadata={"source": "github", "operation": "search_code"},
        )

    def _mock_search_pocs(self, params: Dict[str, Any]) -> MCPResult:
        """Mock PoC search response."""
        cve_id = params.get("cve_id", "")

        return MCPResult(
            tool=self.tool_name,
            operation="search_pocs",
            success=True,
            data={
                "cve_id": cve_id,
                "pocs": [
                    {
                        "repository": "kozmer/log4j-shell-poc",
                        "url": "https://github.com/kozmer/log4j-shell-poc",
                        "stars": 1523,
                        "language": "Python",
                        "description": "A Proof-Of-Concept for the CVE-2021-44228 vulnerability",
                        "last_updated": "2022-01-15",
                        "reliability_score": 0.85,
                        "verified": True,
                    },
                    {
                        "repository": "tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce",
                        "url": "https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce",
                        "stars": 856,
                        "language": "Python",
                        "description": "Apache Log4j Remote Code Execution",
                        "last_updated": "2022-01-10",
                        "reliability_score": 0.75,
                        "verified": False,
                    },
                    {
                        "repository": "fullhunt/log4j-scan",
                        "url": "https://github.com/fullhunt/log4j-scan",
                        "stars": 3200,
                        "language": "Python",
                        "description": "A fully automated, accurate, and extensive scanner for finding log4j RCE CVE-2021-44228",
                        "last_updated": "2022-03-20",
                        "reliability_score": 0.95,
                        "verified": True,
                    },
                ],
                "total": 3,
            },
            metadata={"source": "github", "operation": "search_pocs"},
        )

    def _mock_get_repo_info(self, params: Dict[str, Any]) -> MCPResult:
        """Mock repository info response."""
        repo = params.get("repo", "")

        return MCPResult(
            tool=self.tool_name,
            operation="get_repo_info",
            success=True,
            data={
                "full_name": repo,
                "description": "A Proof-Of-Concept for the CVE-2021-44228 vulnerability",
                "url": f"https://github.com/{repo}",
                "stars": 1523,
                "forks": 432,
                "watchers": 89,
                "language": "Python",
                "license": "MIT",
                "created_at": "2021-12-10T14:00:00Z",
                "updated_at": "2022-01-15T10:30:00Z",
                "topics": ["cve-2021-44228", "log4j", "poc", "exploit", "security"],
                "default_branch": "main",
                "open_issues": 12,
                "contributors_count": 15,
                "readme_content": "# Log4j Shell PoC\n\nThis is a PoC for CVE-2021-44228...",
            },
            metadata={"source": "github", "operation": "get_repo_info"},
        )

    def _mock_get_repo_contents(self, params: Dict[str, Any]) -> MCPResult:
        """Mock repository contents response."""
        repo = params.get("repo", "")
        path = params.get("path", "")

        return MCPResult(
            tool=self.tool_name,
            operation="get_repo_contents",
            success=True,
            data={
                "repository": repo,
                "path": path,
                "type": "file",
                "content": "#!/usr/bin/env python3\n# Log4j PoC\nimport socket\n...",
                "size": 2048,
                "encoding": "utf-8",
            },
            metadata={"source": "github", "operation": "get_repo_contents"},
        )

    def _mock_search_exploits(self, params: Dict[str, Any]) -> MCPResult:
        """Mock exploit search response."""
        cve_id = params.get("cve_id", "")
        product = params.get("product", "")

        return MCPResult(
            tool=self.tool_name,
            operation="search_exploits",
            success=True,
            data={
                "cve_id": cve_id,
                "product": product,
                "exploits": [
                    {
                        "repository": "kozmer/log4j-shell-poc",
                        "type": "rce",
                        "language": "Python",
                        "stars": 1523,
                        "description": "Remote Code Execution PoC",
                        "requirements": ["python3", "ldap server"],
                        "difficulty": "easy",
                        "reliability": "high",
                        "last_tested": "2022-01-10",
                    },
                    {
                        "repository": "feihong-cs/log4shell-payload-generator",
                        "type": "payload_generator",
                        "language": "Java",
                        "stars": 456,
                        "description": "Generates various Log4Shell payloads",
                        "requirements": ["java"],
                        "difficulty": "medium",
                        "reliability": "medium",
                        "last_tested": "2022-01-05",
                    },
                ],
                "total": 2,
            },
            metadata={"source": "github", "operation": "search_exploits"},
        )

    def _mock_evaluate_reliability(self, params: Dict[str, Any]) -> MCPResult:
        """Mock reliability evaluation response."""
        repo = params.get("repo", "")

        return MCPResult(
            tool=self.tool_name,
            operation="evaluate_reliability",
            success=True,
            data={
                "repository": repo,
                "reliability_score": 0.85,
                "factors": {
                    "stars": {"value": 1523, "score": 0.9, "weight": 0.2},
                    "forks": {"value": 432, "score": 0.8, "weight": 0.1},
                    "recency": {"value": "2022-01-15", "score": 0.7, "weight": 0.2},
                    "documentation": {"value": True, "score": 0.9, "weight": 0.15},
                    "issues_resolved": {"value": 0.85, "score": 0.85, "weight": 0.1},
                    "contributors": {"value": 15, "score": 0.8, "weight": 0.1},
                    "license": {"value": "MIT", "score": 1.0, "weight": 0.05},
                    "verified": {"value": True, "score": 1.0, "weight": 0.1},
                },
                "recommendation": "high",
                "warnings": [],
            },
            metadata={"source": "github", "operation": "evaluate_reliability"},
        )

    # Convenience methods

    def search_repositories(
        self,
        query: str,
        language: Optional[str] = None,
        sort: str = "stars",
    ) -> MCPResult:
        """
        Search GitHub repositories.

        Args:
            query: Search query
            language: Filter by language
            sort: Sort by (stars, forks, updated)

        Returns:
            MCPResult with matching repositories.
        """
        params = {"query": query, "sort": sort}
        if language:
            params["language"] = language
        return self.invoke("search_repos", params)

    def search_code(
        self,
        query: str,
        language: Optional[str] = None,
    ) -> MCPResult:
        """
        Search code on GitHub.

        Args:
            query: Code search query
            language: Filter by language

        Returns:
            MCPResult with code matches.
        """
        params = {"query": query}
        if language:
            params["language"] = language
        return self.invoke("search_code", params)

    def search_pocs_for_cve(self, cve_id: str) -> MCPResult:
        """
        Search for PoC repositories for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            MCPResult with PoC repositories.
        """
        return self.invoke("search_pocs", {"cve_id": cve_id})

    def get_repository_info(self, repo: str) -> MCPResult:
        """
        Get repository information.

        Args:
            repo: Repository full name (owner/repo)

        Returns:
            MCPResult with repository details.
        """
        return self.invoke("get_repo_info", {"repo": repo})

    def get_repository_contents(
        self,
        repo: str,
        path: str = "",
    ) -> MCPResult:
        """
        Get repository file contents.

        Args:
            repo: Repository full name
            path: File path

        Returns:
            MCPResult with file contents.
        """
        return self.invoke("get_repo_contents", {"repo": repo, "path": path})

    def search_exploits(
        self,
        cve_id: Optional[str] = None,
        product: Optional[str] = None,
    ) -> MCPResult:
        """
        Search for exploit code.

        Args:
            cve_id: CVE identifier
            product: Product name

        Returns:
            MCPResult with exploit matches.
        """
        params = {}
        if cve_id:
            params["cve_id"] = cve_id
        if product:
            params["product"] = product
        return self.invoke("search_exploits", params)

    def evaluate_poc_reliability(self, repo: str) -> MCPResult:
        """
        Evaluate PoC repository reliability.

        Args:
            repo: Repository full name

        Returns:
            MCPResult with reliability assessment.
        """
        return self.invoke("evaluate_reliability", {"repo": repo})
