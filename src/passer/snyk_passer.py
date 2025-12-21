"""
Snyk Passer - Normalizes Snyk vulnerability scan output into common schema objects.

Parses Snyk JSON output and converts to VulnCandidate objects.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union

from .base import BasePasser, MCPType, PasserRegistry, PasserResult
from ..schemas import VulnCandidate, Observation
from ..schemas.vuln_candidate import Severity, ConfidenceLevel


@PasserRegistry.register
class SnykPasser(BasePasser):
    """
    Passer for Snyk vulnerability scan output.

    Converts Snyk vulnerability reports to VulnCandidate objects.
    """

    mcp_type = MCPType.SNYK
    tool_name = "snyk"

    # Severity mapping from Snyk to our schema
    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "informational": Severity.INFO,
    }

    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """Check if this is Snyk output."""
        data = self._parse_input(raw_output)
        if data is None:
            return False

        # Check for Snyk-specific fields
        snyk_indicators = [
            "vulnerabilities", "projectName", "displayTargetFile",
            "packageManager", "snykVersion", "uniqueCount"
        ]
        return any(key in data for key in snyk_indicators)

    def normalize(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize Snyk output.

        Args:
            raw_output: Snyk JSON output.
            **kwargs: Additional parameters.

        Returns:
            PasserResult with VulnCandidate objects.
        """
        result = self._create_result()

        data = self._parse_input(raw_output)
        if data is None:
            result.add_error("Failed to parse Snyk output as JSON")
            return result

        result.raw_data = data

        # Handle array of results (multiple projects)
        if isinstance(data, list):
            for project_data in data:
                self._parse_project(project_data, result)
        else:
            self._parse_project(data, result)

        # Create summary observation
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

    def _parse_project(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> None:
        """Parse a single project's vulnerabilities."""
        project_name = data.get("projectName", "unknown")
        target_file = data.get("displayTargetFile", "")
        package_manager = data.get("packageManager", "")

        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            vuln_candidate = self._parse_vulnerability(
                vuln, project_name, target_file, package_manager, result
            )
            if vuln_candidate:
                result.vuln_candidates.append(vuln_candidate)

    def _parse_vulnerability(
        self,
        vuln: Dict[str, Any],
        project_name: str,
        target_file: str,
        package_manager: str,
        result: PasserResult,
    ) -> Optional[VulnCandidate]:
        """Parse a single vulnerability into VulnCandidate."""
        try:
            # Get basic info
            vuln_id = vuln.get("id", "")
            title = vuln.get("title", "Unknown Vulnerability")
            severity_str = vuln.get("severity", "medium").lower()
            severity = self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

            # Get CVE IDs
            cve_ids = []
            identifiers = vuln.get("identifiers", {})
            if "CVE" in identifiers:
                cve_ids = identifiers["CVE"]
            cve_id = cve_ids[0] if cve_ids else None

            # Get CVSS score
            cvss_score = None
            cvss_data = vuln.get("cvssScore")
            if cvss_data is not None:
                cvss_score = self._safe_float(cvss_data, result=result)

            # Get affected package
            package_name = vuln.get("packageName", "")
            package_version = vuln.get("version", "")
            affected_component = f"{package_name}@{package_version}" if package_name else target_file

            # Get fix info
            upgradable = vuln.get("isUpgradable", False)
            patchable = vuln.get("isPatchable", False)
            fix_available = upgradable or patchable
            upgrade_path = vuln.get("upgradePath", [])

            # Build description
            description = vuln.get("description", "")
            if not description:
                description = f"Vulnerability in {affected_component}: {title}"

            # Determine confidence based on Snyk's data
            confidence = ConfidenceLevel.HIGH  # Snyk results are generally reliable

            vuln_candidate = VulnCandidate(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                title=title,
                description=description,
                severity=severity,
                cve_id=cve_id,
                cvss_score=cvss_score,
                affected_component=affected_component,
                confidence=confidence,
                source="snyk",
                metadata={
                    "snyk_id": vuln_id,
                    "package_name": package_name,
                    "package_version": package_version,
                    "package_manager": package_manager,
                    "project_name": project_name,
                    "target_file": target_file,
                    "all_cve_ids": cve_ids,
                    "cwe_ids": identifiers.get("CWE", []),
                    "is_upgradable": upgradable,
                    "is_patchable": patchable,
                    "fix_available": fix_available,
                    "upgrade_path": upgrade_path,
                    "exploit_maturity": vuln.get("exploit"),
                    "from_path": vuln.get("from", []),
                    "semver_vulnerable": vuln.get("semver", {}).get("vulnerable"),
                    "publication_time": vuln.get("publicationTime"),
                    "disclosure_time": vuln.get("disclosureTime"),
                    "language": vuln.get("language"),
                    "references": vuln.get("references", []),
                },
            )
            return vuln_candidate
        except Exception as e:
            result.add_warning(f"Failed to parse Snyk vulnerability: {e}")
            return None

    def _create_observation(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]]],
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create an Observation for the Snyk scan."""
        try:
            # Count vulnerabilities by severity
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }

            for vc in result.vuln_candidates:
                sev = vc.severity.value.lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            # Build summary
            total = len(result.vuln_candidates)
            summary_parts = [f"{total} vulnerabilities found"]

            high_severity = severity_counts["critical"] + severity_counts["high"]
            if high_severity > 0:
                summary_parts.append(f"{high_severity} high/critical")

            summary = f"Snyk scan: {', '.join(summary_parts)}"

            # Get project info
            project_name = ""
            if isinstance(data, list) and data:
                project_name = data[0].get("projectName", "")
            elif isinstance(data, dict):
                project_name = data.get("projectName", "")

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="vulnerability_scan",
                summary=summary,
                success=True,
                metadata={
                    "project_name": project_name,
                    "total_vulnerabilities": total,
                    "severity_counts": severity_counts,
                    "vuln_candidate_ids": [vc.id for vc in result.vuln_candidates],
                },
            )
            return observation
        except Exception as e:
            result.add_error(f"Failed to create Observation: {e}")
            return None
