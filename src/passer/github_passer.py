"""
GitHub/GitLab Passer - Normalizes repository search output into common schema objects.

Handles PoC/Exploit repository information and converts to ExploitCandidate objects.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union

from .base import BasePasser, MCPType, PasserRegistry, PasserResult
from ..schemas import ExploitCandidate, Observation
from ..schemas.exploit_candidate import ExploitSource, ExploitReliability


@PasserRegistry.register
class GitHubPasser(BasePasser):
    """
    Passer for GitHub/GitLab repository and code search results.

    Converts repository information to ExploitCandidate objects.
    """

    mcp_type = MCPType.GITHUB
    tool_name = "github"

    # Patterns that indicate PoC/exploit code
    POC_PATTERNS = [
        r"poc", r"proof.?of.?concept", r"exploit", r"cve-\d{4}-\d+",
        r"vulnerability", r"rce", r"sqli", r"xss", r"payload",
    ]

    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """Check if this is GitHub/GitLab output."""
        data = self._parse_input(raw_output)
        if data is None:
            return False

        # Check for GitHub-specific fields
        github_indicators = [
            "full_name", "html_url", "clone_url", "stargazers_count",
            "items", "total_count", "repositories", "repos"
        ]
        return any(key in data for key in github_indicators)

    def normalize(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize GitHub/GitLab output.

        Args:
            raw_output: GitHub API response or search results.
            **kwargs: Additional parameters.

        Returns:
            PasserResult with ExploitCandidate objects.
        """
        result = self._create_result()

        data = self._parse_input(raw_output)
        if data is None:
            result.add_error("Failed to parse GitHub output as JSON")
            return result

        result.raw_data = data

        # Handle search results
        if "items" in data:
            for item in data["items"]:
                exploit = self._parse_repository(item, result)
                if exploit:
                    result.exploit_candidates.append(exploit)
        # Handle array of repositories
        elif isinstance(data, list):
            for item in data:
                exploit = self._parse_repository(item, result)
                if exploit:
                    result.exploit_candidates.append(exploit)
        # Handle single repository
        elif "full_name" in data or "html_url" in data:
            exploit = self._parse_repository(data, result)
            if exploit:
                result.exploit_candidates.append(exploit)
        # Handle repositories wrapper
        elif "repositories" in data or "repos" in data:
            repos = data.get("repositories") or data.get("repos", [])
            for item in repos:
                exploit = self._parse_repository(item, result)
                if exploit:
                    result.exploit_candidates.append(exploit)

        # Create observation
        observation = self._create_observation(data, result)
        if observation:
            result.observations.append(observation)

        return result

    def _parse_input(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
    ) -> Optional[Union[Dict[str, Any], List[Dict[str, Any]]]]:
        """Parse input into dictionary or list."""
        if isinstance(raw_output, (dict, list)):
            return raw_output

        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, str):
            try:
                return json.loads(raw_output)
            except json.JSONDecodeError:
                return None

        return None

    def _parse_repository(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[ExploitCandidate]:
        """Parse a repository into ExploitCandidate."""
        try:
            # Get basic info
            name = data.get("name") or data.get("full_name", "").split("/")[-1]
            full_name = data.get("full_name", name)
            description = data.get("description", "") or ""
            html_url = data.get("html_url", "")
            clone_url = data.get("clone_url", "")

            # Extract CVE if present in name or description
            cve_id = self._extract_cve(name, description)

            # Determine reliability based on stars and other metrics
            reliability = self._assess_reliability(data)

            # Determine source type
            source = ExploitSource.GITHUB
            if "gitlab" in html_url.lower():
                source = ExploitSource.GITLAB

            # Build title
            title = f"PoC: {name}"
            if cve_id:
                title = f"PoC for {cve_id}: {name}"

            # Extract language/platform info
            language = data.get("language", "")
            topics = data.get("topics", [])

            # Get prerequisites from README or description
            prerequisites = self._extract_prerequisites(description, language)

            exploit = ExploitCandidate(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                title=title,
                description=description or f"Exploit/PoC code from {full_name}",
                cve_id=cve_id,
                source=source,
                source_url=html_url,
                reliability=reliability,
                prerequisites=prerequisites,
                metadata={
                    "full_name": full_name,
                    "clone_url": clone_url,
                    "language": language,
                    "topics": topics,
                    "stars": data.get("stargazers_count", 0),
                    "forks": data.get("forks_count", 0),
                    "watchers": data.get("watchers_count", 0),
                    "open_issues": data.get("open_issues_count", 0),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                    "pushed_at": data.get("pushed_at"),
                    "owner": data.get("owner", {}).get("login"),
                    "license": data.get("license", {}).get("key") if data.get("license") else None,
                    "default_branch": data.get("default_branch"),
                    "archived": data.get("archived", False),
                    "disabled": data.get("disabled", False),
                },
            )
            return exploit
        except Exception as e:
            result.add_warning(f"Failed to parse repository: {e}")
            return None

    def _extract_cve(self, name: str, description: str) -> Optional[str]:
        """Extract CVE ID from name or description."""
        text = f"{name} {description}".upper()
        match = re.search(r"CVE-\d{4}-\d+", text)
        return match.group(0) if match else None

    def _assess_reliability(self, data: Dict[str, Any]) -> ExploitReliability:
        """Assess exploit reliability based on repository metrics."""
        stars = data.get("stargazers_count", 0)
        forks = data.get("forks_count", 0)
        archived = data.get("archived", False)
        disabled = data.get("disabled", False)

        # Penalize archived or disabled repos
        if archived or disabled:
            return ExploitReliability.UNRELIABLE

        # High reliability for popular repos
        if stars >= 100 or forks >= 50:
            return ExploitReliability.EXCELLENT

        if stars >= 20 or forks >= 10:
            return ExploitReliability.GOOD

        if stars >= 5 or forks >= 2:
            return ExploitReliability.FUNCTIONAL

        # New/unknown repos are untested
        return ExploitReliability.UNTESTED

    def _extract_prerequisites(
        self,
        description: str,
        language: str,
    ) -> List[str]:
        """Extract prerequisites from description and language."""
        prerequisites = []

        # Add language requirement
        if language:
            lang_lower = language.lower()
            if lang_lower == "python":
                prerequisites.append("Python 3.x")
            elif lang_lower == "go":
                prerequisites.append("Go runtime")
            elif lang_lower == "ruby":
                prerequisites.append("Ruby interpreter")
            elif lang_lower == "javascript" or lang_lower == "typescript":
                prerequisites.append("Node.js")
            elif lang_lower == "c" or lang_lower == "c++":
                prerequisites.append("C/C++ compiler")
            elif lang_lower == "rust":
                prerequisites.append("Rust toolchain")
            elif lang_lower == "java":
                prerequisites.append("Java Runtime")
            elif lang_lower == "shell":
                prerequisites.append("Bash shell")

        # Look for common dependencies in description
        desc_lower = description.lower() if description else ""

        if "docker" in desc_lower:
            prerequisites.append("Docker")
        if "kali" in desc_lower:
            prerequisites.append("Kali Linux")
        if "metasploit" in desc_lower or "msf" in desc_lower:
            prerequisites.append("Metasploit Framework")
        if "burp" in desc_lower:
            prerequisites.append("Burp Suite")
        if "nmap" in desc_lower:
            prerequisites.append("Nmap")

        return prerequisites

    def _create_observation(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]]],
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create an Observation for the GitHub search."""
        try:
            total = len(result.exploit_candidates)

            # Get total count from search results
            search_total = None
            if isinstance(data, dict):
                search_total = data.get("total_count")

            summary_parts = [f"{total} exploits/PoCs found"]
            if search_total and search_total > total:
                summary_parts.append(f"({search_total} total results)")

            # Count CVE-related
            cve_count = sum(1 for ec in result.exploit_candidates if ec.cve_id)
            if cve_count:
                summary_parts.append(f"{cve_count} with CVE")

            summary = f"GitHub search: {', '.join(summary_parts)}"

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="repository_search",
                summary=summary,
                success=True,
                metadata={
                    "total_found": total,
                    "search_total": search_total,
                    "cve_related_count": cve_count,
                    "exploit_candidate_ids": [ec.id for ec in result.exploit_candidates],
                },
            )
            return observation
        except Exception as e:
            result.add_error(f"Failed to create Observation: {e}")
            return None
