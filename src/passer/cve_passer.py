"""
CVE Research Passer - Normalizes CVE research output into common schema objects.

Handles CVE database responses and converts to VulnCandidate objects.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Union

from .base import BasePasser, MCPType, PasserRegistry, PasserResult
from ..schemas import VulnCandidate, Observation
from ..schemas.vuln_candidate import Severity, ConfidenceLevel


@PasserRegistry.register
class CvePasser(BasePasser):
    """
    Passer for CVE research output.

    Handles NVD, MITRE, and other CVE database responses.
    """

    mcp_type = MCPType.CVE
    tool_name = "cve-research"

    # CVSS score to severity mapping
    CVSS_SEVERITY_MAP = [
        (9.0, Severity.CRITICAL),
        (7.0, Severity.HIGH),
        (4.0, Severity.MEDIUM),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
    ]

    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """Check if this is CVE research output."""
        data = self._parse_input(raw_output)
        if data is None:
            return False

        # Check for CVE-specific fields
        cve_indicators = [
            "CVE", "cve", "cveId", "cve_id", "vulnerabilities",
            "CVE_data_meta", "CVE_Items", "result"
        ]

        # Check top-level keys
        if any(key in data for key in cve_indicators):
            return True

        # Check for CVE pattern in values
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, str) and re.match(r"CVE-\d{4}-\d+", value):
                    return True

        return False

    def normalize(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize CVE research output.

        Args:
            raw_output: CVE database response.
            **kwargs: Additional parameters.

        Returns:
            PasserResult with VulnCandidate objects.
        """
        result = self._create_result()

        data = self._parse_input(raw_output)
        if data is None:
            result.add_error("Failed to parse CVE output as JSON")
            return result

        result.raw_data = data

        # Handle different CVE response formats
        if "CVE_Items" in data:
            # NVD format
            self._parse_nvd_format(data, result)
        elif "vulnerabilities" in data:
            # NVD 2.0 format
            self._parse_nvd2_format(data, result)
        elif "cve" in data or "CVE" in data:
            # Single CVE
            cve_data = data.get("cve") or data.get("CVE") or data
            vuln = self._parse_cve_entry(cve_data, result)
            if vuln:
                result.vuln_candidates.append(vuln)
        elif "result" in data:
            # Wrapped result
            self._parse_result_format(data["result"], result)
        else:
            # Try to parse as single CVE
            vuln = self._parse_cve_entry(data, result)
            if vuln:
                result.vuln_candidates.append(vuln)

        # Create observation
        observation = self._create_observation(data, result)
        if observation:
            result.observations.append(observation)

        return result

    def _parse_input(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Parse input into dictionary."""
        if isinstance(raw_output, dict):
            return raw_output

        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, str):
            try:
                return json.loads(raw_output)
            except json.JSONDecodeError:
                return None

        return None

    def _parse_nvd_format(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> None:
        """Parse NVD 1.1 format."""
        for item in data.get("CVE_Items", []):
            cve_data = item.get("cve", {})
            impact = item.get("impact", {})

            vuln = self._parse_cve_with_impact(cve_data, impact, result)
            if vuln:
                result.vuln_candidates.append(vuln)

    def _parse_nvd2_format(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> None:
        """Parse NVD 2.0 format."""
        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            vuln = self._parse_nvd2_cve(cve_data, result)
            if vuln:
                result.vuln_candidates.append(vuln)

    def _parse_result_format(
        self,
        data: Union[Dict[str, Any], List[Dict[str, Any]]],
        result: PasserResult,
    ) -> None:
        """Parse wrapped result format."""
        if isinstance(data, list):
            for item in data:
                vuln = self._parse_cve_entry(item, result)
                if vuln:
                    result.vuln_candidates.append(vuln)
        else:
            vuln = self._parse_cve_entry(data, result)
            if vuln:
                result.vuln_candidates.append(vuln)

    def _parse_cve_entry(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[VulnCandidate]:
        """Parse a generic CVE entry."""
        try:
            # Extract CVE ID
            cve_id = (
                data.get("cveId") or
                data.get("cve_id") or
                data.get("id") or
                data.get("CVE_data_meta", {}).get("ID") or
                data.get("CVE")
            )

            if not cve_id:
                result.add_warning("CVE entry missing ID")
                return None

            # Extract description
            description = self._extract_description(data)

            # Extract CVSS
            cvss_score, severity = self._extract_cvss(data)

            # Extract affected products
            affected = self._extract_affected(data)

            # Build title
            title = f"{cve_id}"
            if description:
                # Use first sentence as title addition
                first_sentence = description.split(".")[0]
                if len(first_sentence) < 100:
                    title = f"{cve_id}: {first_sentence}"

            vuln = VulnCandidate(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                title=title,
                description=description or f"Vulnerability {cve_id}",
                severity=severity,
                cve_id=cve_id,
                cvss_score=cvss_score,
                affected_component=affected,
                confidence=ConfidenceLevel.HIGH,  # CVE data is authoritative
                source="cve-research",
                references=self._extract_references(data),
                metadata={
                    "cwe_ids": self._extract_cwe(data),
                    "published_date": data.get("publishedDate") or data.get("published"),
                    "last_modified": data.get("lastModifiedDate") or data.get("lastModified"),
                    "assigner": data.get("assigner") or data.get("sourceIdentifier"),
                    "vuln_status": data.get("vulnStatus"),
                },
            )
            return vuln
        except Exception as e:
            result.add_warning(f"Failed to parse CVE entry: {e}")
            return None

    def _parse_cve_with_impact(
        self,
        cve_data: Dict[str, Any],
        impact: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[VulnCandidate]:
        """Parse CVE with separate impact data (NVD 1.1)."""
        try:
            cve_id = cve_data.get("CVE_data_meta", {}).get("ID")
            if not cve_id:
                return None

            # Get description
            description = ""
            desc_data = cve_data.get("description", {}).get("description_data", [])
            for desc in desc_data:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Get CVSS from impact
            cvss_score = None
            severity = Severity.MEDIUM

            if "baseMetricV3" in impact:
                cvss_v3 = impact["baseMetricV3"].get("cvssV3", {})
                cvss_score = self._safe_float(cvss_v3.get("baseScore"), result=result)
                severity = self._cvss_to_severity(cvss_score)
            elif "baseMetricV2" in impact:
                cvss_v2 = impact["baseMetricV2"].get("cvssV2", {})
                cvss_score = self._safe_float(cvss_v2.get("baseScore"), result=result)
                severity = self._cvss_to_severity(cvss_score)

            # Get affected
            affected = self._extract_affected_from_nodes(
                cve_data.get("configurations", {}).get("nodes", [])
            )

            vuln = VulnCandidate(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                title=f"{cve_id}",
                description=description or f"Vulnerability {cve_id}",
                severity=severity,
                cve_id=cve_id,
                cvss_score=cvss_score,
                affected_component=affected,
                confidence=ConfidenceLevel.HIGH,
                source="cve-research",
                references=self._extract_references(cve_data),
            )
            return vuln
        except Exception as e:
            result.add_warning(f"Failed to parse CVE with impact: {e}")
            return None

    def _parse_nvd2_cve(
        self,
        cve_data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[VulnCandidate]:
        """Parse NVD 2.0 CVE format."""
        try:
            cve_id = cve_data.get("id")
            if not cve_id:
                return None

            # Get description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Get CVSS from metrics
            cvss_score = None
            severity = Severity.MEDIUM
            metrics = cve_data.get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = self._safe_float(cvss_data.get("baseScore"), result=result)
                severity = self._cvss_to_severity(cvss_score)
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = self._safe_float(cvss_data.get("baseScore"), result=result)
                severity = self._cvss_to_severity(cvss_score)

            # Get references
            references = [
                ref.get("url") for ref in cve_data.get("references", [])
                if ref.get("url")
            ]

            vuln = VulnCandidate(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                title=cve_id,
                description=description or f"Vulnerability {cve_id}",
                severity=severity,
                cve_id=cve_id,
                cvss_score=cvss_score,
                affected_component=self._extract_affected(cve_data),
                confidence=ConfidenceLevel.HIGH,
                source="cve-research",
                references=references,
                metadata={
                    "published": cve_data.get("published"),
                    "last_modified": cve_data.get("lastModified"),
                    "vuln_status": cve_data.get("vulnStatus"),
                },
            )
            return vuln
        except Exception as e:
            result.add_warning(f"Failed to parse NVD2 CVE: {e}")
            return None

    def _extract_description(self, data: Dict[str, Any]) -> str:
        """Extract description from various formats."""
        # Direct description
        if "description" in data:
            desc = data["description"]
            if isinstance(desc, str):
                return desc
            if isinstance(desc, dict):
                desc_data = desc.get("description_data", [])
                for d in desc_data:
                    if d.get("lang") == "en":
                        return d.get("value", "")
            if isinstance(desc, list):
                for d in desc:
                    if d.get("lang") == "en":
                        return d.get("value", "")

        # descriptions array (NVD 2.0)
        for desc in data.get("descriptions", []):
            if desc.get("lang") == "en":
                return desc.get("value", "")

        return ""

    def _extract_cvss(
        self,
        data: Dict[str, Any],
    ) -> tuple[Optional[float], Severity]:
        """Extract CVSS score and derive severity."""
        # Direct cvss field
        if "cvss" in data:
            score = self._safe_float(data["cvss"])
            if score:
                return score, self._cvss_to_severity(score)

        # cvssScore field
        if "cvssScore" in data:
            score = self._safe_float(data["cvssScore"])
            if score:
                return score, self._cvss_to_severity(score)

        # Nested impact
        impact = data.get("impact", {})
        if "baseMetricV3" in impact:
            score = self._safe_float(
                impact["baseMetricV3"].get("cvssV3", {}).get("baseScore")
            )
            if score:
                return score, self._cvss_to_severity(score)

        # Direct severity field
        severity_str = data.get("severity", "").lower()
        if severity_str:
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            return None, severity_map.get(severity_str, Severity.MEDIUM)

        return None, Severity.MEDIUM

    def _cvss_to_severity(self, score: Optional[float]) -> Severity:
        """Convert CVSS score to severity."""
        if score is None:
            return Severity.MEDIUM

        for threshold, severity in self.CVSS_SEVERITY_MAP:
            if score >= threshold:
                return severity

        return Severity.INFO

    def _extract_affected(self, data: Dict[str, Any]) -> str:
        """Extract affected component."""
        # Direct affected field
        if "affected" in data:
            affected = data["affected"]
            if isinstance(affected, str):
                return affected
            if isinstance(affected, list) and affected:
                return ", ".join(str(a) for a in affected[:3])

        # affected_component field
        if "affected_component" in data:
            return data["affected_component"]

        # configurations (NVD format)
        if "configurations" in data:
            nodes = data["configurations"].get("nodes", [])
            return self._extract_affected_from_nodes(nodes)

        return "Unknown"

    def _extract_affected_from_nodes(self, nodes: List[Dict[str, Any]]) -> str:
        """Extract affected from configuration nodes."""
        affected = []
        for node in nodes[:3]:  # Limit to first 3 nodes
            for cpe_match in node.get("cpe_match", [])[:3]:
                cpe = cpe_match.get("cpe23Uri", "") or cpe_match.get("criteria", "")
                if cpe:
                    # Extract product name from CPE
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        affected.append(f"{vendor}/{product}")
        return ", ".join(affected) if affected else "Unknown"

    def _extract_cwe(self, data: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs."""
        cwe_ids = []

        # Direct cwe field
        if "cwe" in data:
            cwe = data["cwe"]
            if isinstance(cwe, str):
                cwe_ids.append(cwe)
            elif isinstance(cwe, list):
                cwe_ids.extend(cwe)

        # weaknesses (NVD 2.0)
        for weakness in data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwe_ids.append(value)

        # problemtype (NVD 1.1)
        problemtype = data.get("problemtype", {})
        for pt_data in problemtype.get("problemtype_data", []):
            for desc in pt_data.get("description", []):
                value = desc.get("value", "")
                if value.startswith("CWE-"):
                    cwe_ids.append(value)

        return list(set(cwe_ids))

    def _extract_references(self, data: Dict[str, Any]) -> List[str]:
        """Extract reference URLs."""
        refs = []

        # Direct references
        for ref in data.get("references", []):
            if isinstance(ref, str):
                refs.append(ref)
            elif isinstance(ref, dict):
                url = ref.get("url")
                if url:
                    refs.append(url)

        # reference_data (NVD format)
        ref_data = data.get("references", {}).get("reference_data", [])
        for ref in ref_data:
            url = ref.get("url")
            if url:
                refs.append(url)

        return refs

    def _create_observation(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create an Observation for the CVE research."""
        try:
            total = len(result.vuln_candidates)
            summary = f"CVE research: {total} vulnerabilities found"

            # Count by severity
            severity_counts = {}
            for vc in result.vuln_candidates:
                sev = vc.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="cve_lookup",
                summary=summary,
                success=True,
                metadata={
                    "total_cves": total,
                    "severity_counts": severity_counts,
                    "vuln_candidate_ids": [vc.id for vc in result.vuln_candidates],
                },
            )
            return observation
        except Exception as e:
            result.add_error(f"Failed to create Observation: {e}")
            return None
