"""
Reporting Agent for PentestAgent.

Generates final penetration testing reports from findings.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base_agent import (
    BaseAgent,
    AgentConfig,
    AgentContext,
    AgentOutput,
    AgentType,
)
from ..patch.patch import Patch, PatchOperation
from ..patch.operations import OperationType


@dataclass
class Finding:
    """Verified security finding."""
    finding_id: str
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    impact: str
    affected_component: str
    evidence_ids: List[str]
    reproduction_steps: List[str]
    remediation: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    verified: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "impact": self.impact,
            "affected_component": self.affected_component,
            "evidence_ids": self.evidence_ids,
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "verified": self.verified,
        }


@dataclass
class ReportSection:
    """A section of the report."""
    section_id: str
    title: str
    content: str
    order: int
    subsections: List["ReportSection"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "section_id": self.section_id,
            "title": self.title,
            "content": self.content,
            "order": self.order,
            "subsections": [s.to_dict() for s in self.subsections],
        }


@dataclass
class PentestReport:
    """Complete penetration testing report."""
    report_id: str
    title: str
    executive_summary: str
    scope: Dict[str, Any]
    methodology: str
    findings: List[Finding]
    statistics: Dict[str, Any]
    recommendations: List[str]
    sections: List[ReportSection]
    generated_at: datetime = field(default_factory=datetime.utcnow)
    format_version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "executive_summary": self.executive_summary,
            "scope": self.scope,
            "methodology": self.methodology,
            "findings": [f.to_dict() for f in self.findings],
            "statistics": self.statistics,
            "recommendations": self.recommendations,
            "sections": [s.to_dict() for s in self.sections],
            "generated_at": self.generated_at.isoformat() + "Z",
            "format_version": self.format_version,
        }

    def to_json(self, indent: int = 2) -> str:
        """Export report as JSON."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def to_markdown(self) -> str:
        """Export report as Markdown."""
        lines = []

        # Title
        lines.append(f"# {self.title}")
        lines.append("")
        lines.append(f"**Report ID:** {self.report_id}")
        lines.append(f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(self.executive_summary)
        lines.append("")

        # Statistics
        lines.append("## Summary Statistics")
        lines.append("")
        lines.append(f"| Severity | Count |")
        lines.append("|----------|-------|")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = self.statistics.get("by_severity", {}).get(severity, 0)
            if count > 0:
                lines.append(f"| {severity.capitalize()} | {count} |")
        lines.append("")
        lines.append(f"**Total Findings:** {self.statistics.get('total_findings', 0)}")
        lines.append(f"**Verified Findings:** {self.statistics.get('verified_findings', 0)}")
        lines.append("")

        # Scope
        lines.append("## Scope")
        lines.append("")
        targets = self.scope.get("targets", [])
        if targets:
            for target in targets:
                target_type = target.get("type", "unknown")
                target_value = target.get("value", "")
                lines.append(f"- **{target_type}:** {target_value}")
        lines.append("")

        # Methodology
        lines.append("## Methodology")
        lines.append("")
        lines.append(self.methodology)
        lines.append("")

        # Findings
        lines.append("## Findings")
        lines.append("")

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        for severity in severity_order:
            severity_findings = [f for f in self.findings if f.severity == severity]
            if severity_findings:
                lines.append(f"### {severity.capitalize()} Severity")
                lines.append("")

                for i, finding in enumerate(severity_findings, 1):
                    lines.append(f"#### {i}. {finding.title}")
                    lines.append("")

                    if finding.cve_id:
                        lines.append(f"**CVE:** {finding.cve_id}")
                    if finding.cvss_score:
                        lines.append(f"**CVSS Score:** {finding.cvss_score}")
                    lines.append(f"**Affected Component:** {finding.affected_component}")
                    lines.append("")

                    lines.append("**Description:**")
                    lines.append(finding.description)
                    lines.append("")

                    lines.append("**Impact:**")
                    lines.append(finding.impact)
                    lines.append("")

                    lines.append("**Reproduction Steps:**")
                    for step in finding.reproduction_steps:
                        lines.append(f"1. {step}")
                    lines.append("")

                    lines.append("**Remediation:**")
                    lines.append(finding.remediation)
                    lines.append("")
                    lines.append("---")
                    lines.append("")

        # Recommendations
        lines.append("## Recommendations")
        lines.append("")
        for i, rec in enumerate(self.recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

        return "\n".join(lines)


class ReportingAgent(BaseAgent):
    """
    Reporting Agent.

    Responsibilities:
    - Collect and validate findings
    - Generate executive summary
    - Create detailed findings report
    - Generate remediation recommendations
    - Support multiple output formats
    """

    # Severity ordering for sorting
    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        mock_mode: bool = False,
    ):
        """
        Initialize Reporting Agent.

        Args:
            config: Agent configuration.
            mock_mode: If True, use mock data for testing.
        """
        if config is None:
            config = AgentConfig(
                agent_type=AgentType.REPORTING,
                timeout_seconds=300,  # 5 minutes
            )

        super().__init__(config)
        self.mock_mode = mock_mode

        # Results storage
        self._findings: List[Finding] = []
        self._observations: List[Dict[str, Any]] = []
        self._report: Optional[PentestReport] = None

    def _execute(self, context: AgentContext) -> AgentOutput:
        """
        Execute report generation.

        Args:
            context: Agent context.

        Returns:
            AgentOutput with results.
        """
        self._findings = []
        self._observations = []
        self._report = None

        # Extract findings from context
        self._extract_findings(context)

        if not self._findings:
            self._record_decision(
                "no_findings",
                "No findings to report",
                "No verified findings found in context",
            )
            # Create empty report
            self._report = self._create_empty_report(context)
        else:
            self._record_decision(
                "findings_collected",
                f"Collected {len(self._findings)} findings",
                "Processing findings for report generation",
            )

            # Sort findings by severity
            self._findings.sort(
                key=lambda f: (self.SEVERITY_ORDER.get(f.severity, 5), f.title)
            )

            # Generate report
            self._report = self._generate_report(context)

        # Generate patch
        operations = self._generate_operations()
        patch = self._create_patch(context, operations)

        # Create phase result
        phase_result = {
            "report_id": self._report.report_id,
            "total_findings": len(self._findings),
            "findings_by_severity": self._report.statistics.get("by_severity", {}),
            "report_generated": True,
        }

        return self._create_success_output(context, patch, phase_result)

    def _extract_findings(self, context: AgentContext) -> None:
        """Extract findings from context."""
        target_profile = context.target_profile or {}

        # Get finding candidates
        finding_candidates = target_profile.get("finding_candidates", [])

        for fc in finding_candidates:
            # Only include verified findings or all if none verified
            if fc.get("verified", False) or not any(
                f.get("verified", False) for f in finding_candidates
            ):
                finding = Finding(
                    finding_id=fc.get("finding_id", f"finding-{uuid.uuid4().hex[:8]}"),
                    title=fc.get("title", "Unknown Finding"),
                    severity=fc.get("severity", "medium"),
                    description=fc.get("description", ""),
                    impact=fc.get("impact", ""),
                    affected_component=fc.get("affected_component", "Unknown"),
                    evidence_ids=fc.get("evidence_ids", []),
                    reproduction_steps=fc.get("reproduction_steps", []),
                    remediation=fc.get("remediation", ""),
                    cve_id=fc.get("cve_id"),
                    cvss_score=fc.get("cvss_score"),
                    verified=fc.get("verified", False),
                )
                self._findings.append(finding)

                self._add_observation(
                    "finding_included",
                    f"Including finding: {finding.title}",
                    {"finding_id": finding.finding_id, "severity": finding.severity},
                )

    def _generate_report(self, context: AgentContext) -> PentestReport:
        """Generate the complete report."""
        scope = context.scope or {}
        target_profile = context.target_profile or {}

        # Calculate statistics
        statistics = self._calculate_statistics()

        # Generate executive summary
        executive_summary = self._generate_executive_summary(statistics)

        # Generate methodology
        methodology = self._generate_methodology()

        # Generate recommendations
        recommendations = self._generate_recommendations()

        # Generate report sections
        sections = self._generate_sections(context)

        # Determine report title
        scope_tag = context.scope_tag or "Penetration Test"
        title = f"Penetration Testing Report - {scope_tag}"

        return PentestReport(
            report_id=f"report-{uuid.uuid4().hex[:8]}",
            title=title,
            executive_summary=executive_summary,
            scope=scope,
            methodology=methodology,
            findings=self._findings,
            statistics=statistics,
            recommendations=recommendations,
            sections=sections,
        )

    def _create_empty_report(self, context: AgentContext) -> PentestReport:
        """Create an empty report when no findings."""
        scope = context.scope or {}
        scope_tag = context.scope_tag or "Penetration Test"

        return PentestReport(
            report_id=f"report-{uuid.uuid4().hex[:8]}",
            title=f"Penetration Testing Report - {scope_tag}",
            executive_summary="No security vulnerabilities were identified during this assessment.",
            scope=scope,
            methodology=self._generate_methodology(),
            findings=[],
            statistics={
                "total_findings": 0,
                "verified_findings": 0,
                "by_severity": {},
            },
            recommendations=[
                "Continue regular security assessments",
                "Maintain security awareness training",
                "Keep all systems and dependencies up to date",
            ],
            sections=[],
        )

    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate report statistics."""
        by_severity: Dict[str, int] = {}
        verified_count = 0

        for finding in self._findings:
            severity = finding.severity
            by_severity[severity] = by_severity.get(severity, 0) + 1
            if finding.verified:
                verified_count += 1

        # Calculate risk score
        risk_weights = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1,
            "info": 0,
        }
        risk_score = sum(
            by_severity.get(sev, 0) * weight
            for sev, weight in risk_weights.items()
        )

        # Determine overall risk level
        if by_severity.get("critical", 0) > 0 or risk_score >= 20:
            risk_level = "Critical"
        elif by_severity.get("high", 0) > 0 or risk_score >= 10:
            risk_level = "High"
        elif by_severity.get("medium", 0) > 0 or risk_score >= 5:
            risk_level = "Medium"
        elif by_severity.get("low", 0) > 0:
            risk_level = "Low"
        else:
            risk_level = "Informational"

        return {
            "total_findings": len(self._findings),
            "verified_findings": verified_count,
            "by_severity": by_severity,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "components_affected": len(set(f.affected_component for f in self._findings)),
            "cves_referenced": len([f for f in self._findings if f.cve_id]),
        }

    def _generate_executive_summary(self, statistics: Dict[str, Any]) -> str:
        """Generate executive summary."""
        total = statistics["total_findings"]
        risk_level = statistics["risk_level"]
        by_severity = statistics["by_severity"]

        lines = []

        # Opening statement
        if total == 0:
            return "The security assessment did not identify any vulnerabilities within the defined scope."

        lines.append(
            f"This penetration test identified {total} security "
            f"{'vulnerability' if total == 1 else 'vulnerabilities'} "
            f"with an overall risk level of **{risk_level}**."
        )

        # Severity breakdown
        severity_parts = []
        for sev in ["critical", "high", "medium", "low"]:
            count = by_severity.get(sev, 0)
            if count > 0:
                severity_parts.append(f"{count} {sev}")

        if severity_parts:
            lines.append(f"The findings include: {', '.join(severity_parts)}.")

        # Critical findings highlight
        critical_count = by_severity.get("critical", 0)
        if critical_count > 0:
            lines.append(
                f"**Immediate attention is required** for {critical_count} critical "
                f"{'vulnerability' if critical_count == 1 else 'vulnerabilities'} "
                "that could result in complete system compromise."
            )

        # High findings
        high_count = by_severity.get("high", 0)
        if high_count > 0:
            lines.append(
                f"{high_count} high severity {'issue requires' if high_count == 1 else 'issues require'} "
                "prompt remediation to prevent potential security breaches."
            )

        return " ".join(lines)

    def _generate_methodology(self) -> str:
        """Generate methodology section."""
        return """The assessment followed a structured penetration testing methodology:

1. **Reconnaissance**: Information gathering about the target systems including DNS enumeration, WHOIS lookups, and technology fingerprinting.

2. **Enumeration**: Active scanning to identify open ports, services, and potential attack vectors.

3. **Vulnerability Analysis**: Identification and validation of security vulnerabilities using automated tools and manual testing.

4. **Exploitation**: Controlled exploitation of identified vulnerabilities to verify their impact and severity.

5. **Reporting**: Documentation of findings with evidence, reproduction steps, and remediation recommendations."""

    def _generate_recommendations(self) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []

        # Critical recommendations
        critical_findings = [f for f in self._findings if f.severity == "critical"]
        if critical_findings:
            recommendations.append(
                "CRITICAL: Immediately address all critical vulnerabilities, "
                "particularly those allowing remote code execution or authentication bypass."
            )

        # High recommendations
        high_findings = [f for f in self._findings if f.severity == "high"]
        if high_findings:
            recommendations.append(
                "HIGH PRIORITY: Remediate high-severity vulnerabilities within 30 days "
                "to prevent potential data breaches."
            )

        # Check for specific vulnerability types
        cve_findings = [f for f in self._findings if f.cve_id]
        if cve_findings:
            recommendations.append(
                "Apply security patches for all identified CVEs and establish "
                "a regular patch management process."
            )

        # SQL injection specific
        sqli_findings = [
            f for f in self._findings
            if "sql" in f.title.lower() or "injection" in f.title.lower()
        ]
        if sqli_findings:
            recommendations.append(
                "Implement parameterized queries and input validation to prevent "
                "SQL injection attacks."
            )

        # Authentication issues
        auth_findings = [
            f for f in self._findings
            if "auth" in f.title.lower() or "credential" in f.title.lower()
        ]
        if auth_findings:
            recommendations.append(
                "Strengthen authentication mechanisms including multi-factor authentication "
                "and secure password policies."
            )

        # General recommendations
        recommendations.extend([
            "Implement a Web Application Firewall (WAF) to provide additional protection.",
            "Conduct regular security assessments and penetration tests.",
            "Establish a vulnerability disclosure program.",
            "Provide security awareness training for development teams.",
        ])

        return recommendations

    def _generate_sections(self, context: AgentContext) -> List[ReportSection]:
        """Generate report sections."""
        sections = []

        # Target information section
        target_profile = context.target_profile or {}
        targets = target_profile.get("targets", {})

        if targets:
            target_lines = []
            for target_id, target_info in targets.items():
                if isinstance(target_info, dict):
                    ip = target_info.get("ip", target_id)
                    hostnames = target_info.get("hostnames", [])
                    ports = target_info.get("ports", [])

                    target_lines.append(f"**{ip}**")
                    if hostnames:
                        target_lines.append(f"  - Hostnames: {', '.join(hostnames)}")
                    if ports:
                        port_list = [str(p) if isinstance(p, int) else str(p.get("port", p)) for p in ports[:10]]
                        target_lines.append(f"  - Open Ports: {', '.join(port_list)}")

            sections.append(ReportSection(
                section_id=f"section-{uuid.uuid4().hex[:8]}",
                title="Target Information",
                content="\n".join(target_lines),
                order=1,
            ))

        # Technologies section
        technologies = target_profile.get("technologies", {})
        if technologies:
            tech_lines = []
            for tech_name, tech_info in technologies.items():
                if isinstance(tech_info, dict):
                    version = tech_info.get("version", "Unknown")
                    tech_lines.append(f"- {tech_name}: {version}")
                else:
                    tech_lines.append(f"- {tech_name}: {tech_info}")

            sections.append(ReportSection(
                section_id=f"section-{uuid.uuid4().hex[:8]}",
                title="Identified Technologies",
                content="\n".join(tech_lines),
                order=2,
            ))

        return sections

    def _add_observation(
        self,
        obs_type: str,
        description: str,
        data: Dict[str, Any],
    ) -> None:
        """Add observation record."""
        observation = {
            "observation_id": f"obs-{uuid.uuid4().hex[:8]}",
            "type": obs_type,
            "description": description,
            "data": data,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent": self.agent_type.value,
        }
        self._observations.append(observation)

    def _generate_operations(self) -> List[PatchOperation]:
        """Generate patch operations."""
        operations = []

        # Add observation operations
        for observation in self._observations:
            operations.append(PatchOperation(
                op=OperationType.ADD_OBSERVATION,
                target="observations",
                payload=observation,
            ))

        # Add report to target profile
        if self._report:
            operations.append(PatchOperation(
                op=OperationType.UPDATE_TARGET_PROFILE,
                target="target_profile",
                payload={
                    "report": self._report.to_dict(),
                    "report_json": self._report.to_json(),
                    "report_markdown": self._report.to_markdown(),
                },
            ))

        return operations

    def _should_skip(self, context: AgentContext) -> Optional[str]:
        """Check if reporting should be skipped."""
        target_profile = context.target_profile or {}

        # Skip if report already exists
        if target_profile.get("report"):
            return "Report already generated"

        return None

    def get_report(self) -> Optional[PentestReport]:
        """Get the generated report."""
        return self._report

    def export_json(self) -> Optional[str]:
        """Export report as JSON."""
        if self._report:
            return self._report.to_json()
        return None

    def export_markdown(self) -> Optional[str]:
        """Export report as Markdown."""
        if self._report:
            return self._report.to_markdown()
        return None
