"""Tests for GitHub Passer."""

from __future__ import annotations

import json
import pytest

from src.passer.github_passer import GitHubPasser
from src.passer.base import MCPType
from src.schemas.exploit_candidate import ExploitSource, ExploitReliability


class TestGitHubPasser:
    """Tests for GitHubPasser class."""

    @pytest.fixture
    def passer(self):
        """Create a GitHubPasser instance."""
        return GitHubPasser(
            session_id="test-session",
            scope_tag="test-scope",
            created_by="test",
        )

    def test_mcp_type(self, passer):
        """Test MCP type is correct."""
        assert passer.mcp_type == MCPType.GITHUB

    def test_can_handle_github_json(self, passer):
        """Test can_handle recognizes GitHub JSON."""
        data = {"full_name": "owner/repo", "html_url": "https://github.com/owner/repo"}
        assert passer.can_handle(data) is True

    def test_can_handle_search_results(self, passer):
        """Test can_handle recognizes search results."""
        data = {"total_count": 10, "items": []}
        assert passer.can_handle(data) is True

    def test_cannot_handle_random_data(self, passer):
        """Test can_handle rejects non-GitHub data."""
        assert passer.can_handle({"random": "data"}) is False

    def test_normalize_single_repo(self, passer):
        """Test normalizing single repository."""
        data = {
            "name": "CVE-2021-44228-poc",
            "full_name": "user/CVE-2021-44228-poc",
            "description": "Proof of concept for Log4j CVE-2021-44228",
            "html_url": "https://github.com/user/CVE-2021-44228-poc",
            "clone_url": "https://github.com/user/CVE-2021-44228-poc.git",
            "language": "Python",
            "stargazers_count": 150,
            "forks_count": 30,
            "topics": ["cve", "log4j", "security"],
            "created_at": "2021-12-10T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        }
        result = passer.normalize(data)

        assert result.success
        assert len(result.exploit_candidates) == 1
        assert len(result.observations) == 1

        exploit = result.exploit_candidates[0]
        assert "CVE-2021-44228" in exploit.title
        assert exploit.cve_id == "CVE-2021-44228"
        assert exploit.source == ExploitSource.GITHUB
        assert exploit.source_url == "https://github.com/user/CVE-2021-44228-poc"
        assert exploit.reliability == ExploitReliability.EXCELLENT  # 150 stars
        assert "Python 3.x" in exploit.prerequisites

    def test_normalize_search_results(self, passer):
        """Test normalizing search results."""
        data = {
            "total_count": 2,
            "items": [
                {
                    "name": "exploit1",
                    "full_name": "user1/exploit1",
                    "html_url": "https://github.com/user1/exploit1",
                    "stargazers_count": 5,
                    "forks_count": 1,
                },
                {
                    "name": "exploit2",
                    "full_name": "user2/exploit2",
                    "html_url": "https://github.com/user2/exploit2",
                    "stargazers_count": 50,
                    "forks_count": 10,
                },
            ],
        }
        result = passer.normalize(data)

        assert result.success
        assert len(result.exploit_candidates) == 2

        obs = result.observations[0]
        assert obs.metadata["search_total"] == 2

    def test_reliability_assessment(self, passer):
        """Test reliability assessment based on stars."""
        # Low stars - untested
        data = {"full_name": "x/y", "html_url": "url", "stargazers_count": 1, "forks_count": 0}
        result = passer.normalize(data)
        assert result.exploit_candidates[0].reliability == ExploitReliability.UNTESTED

        # Medium stars - functional
        data = {"full_name": "x/y", "html_url": "url", "stargazers_count": 10, "forks_count": 5}
        result = passer.normalize(data)
        assert result.exploit_candidates[0].reliability == ExploitReliability.FUNCTIONAL

        # High stars - good
        data = {"full_name": "x/y", "html_url": "url", "stargazers_count": 30, "forks_count": 15}
        result = passer.normalize(data)
        assert result.exploit_candidates[0].reliability == ExploitReliability.GOOD

        # Very high stars - excellent
        data = {"full_name": "x/y", "html_url": "url", "stargazers_count": 200, "forks_count": 50}
        result = passer.normalize(data)
        assert result.exploit_candidates[0].reliability == ExploitReliability.EXCELLENT

    def test_archived_repo_unreliable(self, passer):
        """Test archived repos are marked as unreliable."""
        data = {
            "full_name": "x/y",
            "html_url": "url",
            "stargazers_count": 100,
            "archived": True,
        }
        result = passer.normalize(data)
        assert result.exploit_candidates[0].reliability == ExploitReliability.UNRELIABLE

    def test_cve_extraction(self, passer):
        """Test CVE extraction from name and description."""
        # CVE in name
        data = {"name": "CVE-2023-12345", "full_name": "x/CVE-2023-12345", "html_url": "url"}
        result = passer.normalize(data)
        assert result.exploit_candidates[0].cve_id == "CVE-2023-12345"

        # CVE in description
        data = {
            "name": "exploit",
            "full_name": "x/exploit",
            "html_url": "url",
            "description": "Exploit for CVE-2022-99999 vulnerability",
        }
        result = passer.normalize(data)
        assert result.exploit_candidates[0].cve_id == "CVE-2022-99999"

    def test_language_prerequisites(self, passer):
        """Test language-based prerequisites."""
        test_cases = [
            ("Python", "Python 3.x"),
            ("Go", "Go runtime"),
            ("Ruby", "Ruby interpreter"),
            ("JavaScript", "Node.js"),
            ("Rust", "Rust toolchain"),
        ]

        for language, expected_prereq in test_cases:
            data = {"full_name": "x/y", "html_url": "url", "language": language}
            result = passer.normalize(data)
            assert expected_prereq in result.exploit_candidates[0].prerequisites

    def test_normalize_repo_list(self, passer):
        """Test normalizing array of repositories."""
        data = [
            {"full_name": "a/1", "html_url": "url1"},
            {"full_name": "b/2", "html_url": "url2"},
        ]
        result = passer.normalize(data)

        assert result.success
        assert len(result.exploit_candidates) == 2
