"""Tests for GitHub MCP adapter."""

from __future__ import annotations

import pytest

from src.mcp_adapters.github_adapter import GitHubAdapter
from src.mcp_adapters.base_adapter import MCPResult, MCPError


class TestGitHubAdapter:
    """Tests for GitHubAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return GitHubAdapter(mock_mode=True)

    def test_supported_operations(self, adapter):
        """Test getting supported operations."""
        ops = adapter.get_supported_operations()

        assert "search_repos" in ops
        assert "search_code" in ops
        assert "search_pocs" in ops
        assert "get_repo_info" in ops
        assert "get_repo_contents" in ops
        assert "search_exploits" in ops
        assert "evaluate_reliability" in ops

    def test_search_repositories(self, adapter):
        """Test repository search."""
        result = adapter.search_repositories("log4j CVE-2021-44228")

        assert result.success is True
        assert "repositories" in result.data
        assert result.data["total"] > 0

    def test_repository_has_metadata(self, adapter):
        """Test repositories have metadata."""
        result = adapter.search_repositories("log4j")

        assert result.success is True
        for repo in result.data["repositories"]:
            assert "full_name" in repo
            assert "url" in repo
            assert "stars" in repo
            assert "language" in repo

    def test_search_code(self, adapter):
        """Test code search."""
        result = adapter.search_code("jndi:ldap exploit")

        assert result.success is True
        assert "code_results" in result.data

    def test_code_results_have_snippets(self, adapter):
        """Test code results have snippets."""
        result = adapter.search_code("log4j")

        assert result.success is True
        for code in result.data["code_results"]:
            assert "repository" in code
            assert "path" in code
            assert "snippet" in code

    def test_search_pocs_for_cve(self, adapter):
        """Test PoC search for CVE."""
        result = adapter.search_pocs_for_cve("CVE-2021-44228")

        assert result.success is True
        assert result.data["cve_id"] == "CVE-2021-44228"
        assert "pocs" in result.data
        assert result.data["total"] > 0

    def test_pocs_have_reliability_score(self, adapter):
        """Test PoCs have reliability scores."""
        result = adapter.search_pocs_for_cve("CVE-2021-44228")

        assert result.success is True
        for poc in result.data["pocs"]:
            assert "reliability_score" in poc
            assert 0.0 <= poc["reliability_score"] <= 1.0

    def test_pocs_have_verified_status(self, adapter):
        """Test PoCs have verified status."""
        result = adapter.search_pocs_for_cve("CVE-2021-44228")

        assert result.success is True
        for poc in result.data["pocs"]:
            assert "verified" in poc

    def test_get_repository_info(self, adapter):
        """Test getting repository info."""
        result = adapter.get_repository_info("kozmer/log4j-shell-poc")

        assert result.success is True
        assert result.data["full_name"] == "kozmer/log4j-shell-poc"
        assert "stars" in result.data
        assert "forks" in result.data

    def test_repo_info_has_details(self, adapter):
        """Test repo info has detailed metadata."""
        result = adapter.get_repository_info("kozmer/log4j-shell-poc")

        assert result.success is True
        assert "license" in result.data
        assert "topics" in result.data
        assert "contributors_count" in result.data

    def test_get_repository_contents(self, adapter):
        """Test getting repository contents."""
        result = adapter.get_repository_contents("kozmer/log4j-shell-poc", "poc.py")

        assert result.success is True
        assert result.data["repository"] == "kozmer/log4j-shell-poc"
        assert result.data["path"] == "poc.py"
        assert "content" in result.data

    def test_search_exploits(self, adapter):
        """Test exploit search."""
        result = adapter.search_exploits(cve_id="CVE-2021-44228")

        assert result.success is True
        assert "exploits" in result.data

    def test_exploits_have_details(self, adapter):
        """Test exploits have detailed info."""
        result = adapter.search_exploits(cve_id="CVE-2021-44228")

        assert result.success is True
        for exploit in result.data["exploits"]:
            assert "repository" in exploit
            assert "type" in exploit
            assert "difficulty" in exploit
            assert "reliability" in exploit

    def test_evaluate_poc_reliability(self, adapter):
        """Test PoC reliability evaluation."""
        result = adapter.evaluate_poc_reliability("kozmer/log4j-shell-poc")

        assert result.success is True
        assert result.data["repository"] == "kozmer/log4j-shell-poc"
        assert "reliability_score" in result.data
        assert 0.0 <= result.data["reliability_score"] <= 1.0

    def test_reliability_has_factors(self, adapter):
        """Test reliability evaluation includes factors."""
        result = adapter.evaluate_poc_reliability("kozmer/log4j-shell-poc")

        assert result.success is True
        assert "factors" in result.data
        factors = result.data["factors"]
        assert "stars" in factors
        assert "documentation" in factors
        assert "verified" in factors

    def test_reliability_has_recommendation(self, adapter):
        """Test reliability evaluation includes recommendation."""
        result = adapter.evaluate_poc_reliability("kozmer/log4j-shell-poc")

        assert result.success is True
        assert "recommendation" in result.data
        assert result.data["recommendation"] in ["high", "medium", "low"]

    def test_result_to_evidence(self, adapter):
        """Test converting result to evidence format."""
        result = adapter.search_pocs_for_cve("CVE-2021-44228")

        evidence = result.to_evidence()

        assert evidence["source"] == "github"
        assert evidence["source_type"] == "mcp_tool"
        assert "data" in evidence


class TestGitHubAdapterEdgeCases:
    """Edge case tests for GitHubAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return GitHubAdapter(mock_mode=True)

    def test_unsupported_operation(self, adapter):
        """Test unsupported operation returns error result."""
        result = adapter.invoke("unsupported_operation", {})

        assert result.success is False
        assert "Unsupported operation" in result.error

    def test_search_with_language_filter(self, adapter):
        """Test search with language filter."""
        result = adapter.search_repositories("log4j", language="python")

        assert result.success is True

    def test_code_search_with_language(self, adapter):
        """Test code search with language filter."""
        result = adapter.search_code("exploit", language="python")

        assert result.success is True

    def test_search_exploits_by_product(self, adapter):
        """Test exploit search by product."""
        result = adapter.search_exploits(product="log4j")

        assert result.success is True
        assert result.data["product"] == "log4j"
