"""
Report Generator for PentestAgent.

Generates markdown reports from workflow execution results.

FR-8: OPTRS/OWASP-style professional penetration test reports.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from ..orchestrator.workflow import WorkflowState, ExecutionPlan, TaskType
from ..schemas.cvss import CVSS, CVSSVersion, CVSSSeverity
from ..schemas.finding_candidate import FindingCandidate, FindingSeverity
from ..schemas.test_plan import TestPlan, PhaseStatus

if TYPE_CHECKING:
    from ..storage.evidence_ledger import EvidenceLedger


class ReportGenerator:
    """
    Generates penetration test reports from workflow results.
    """

    def __init__(self, output_dir: str = None):
        """
        Initialize report generator.

        Args:
            output_dir: Directory to save reports. Defaults to ~/Downloads.
        """
        if output_dir is None:
            output_dir = str(Path.home() / "Downloads")
        self.output_dir = output_dir

    def generate_report(
        self,
        workflow_state: WorkflowState,
        evidence_ledger: Any = None,
    ) -> str:
        """
        Generate a markdown report from workflow state.

        Args:
            workflow_state: Completed workflow state.
            evidence_ledger: Optional evidence ledger for raw data access.

        Returns:
            Path to the generated report file.
        """
        target_ip = workflow_state.target_ip
        session_id = workflow_state.session_id
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

        # Build report content
        report = self._build_report(workflow_state, evidence_ledger)

        # Save report
        filename = f"PentestReport_{target_ip.replace('.', '_')}_{timestamp}.md"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report)

        return filepath

    def _build_report(
        self,
        state: WorkflowState,
        evidence_ledger: Any = None,
    ) -> str:
        """Build the full report content."""
        sections = [
            self._build_header(state),
            self._build_summary(state),
            self._build_agent_execution_details(state, evidence_ledger),
            self._build_findings(state),
            self._build_evidence_list(state),
            self._build_timeline(state),
            self._build_footer(state),
        ]

        return "\n".join(sections)

    def _build_header(self, state: WorkflowState) -> str:
        """Build report header."""
        return f"""# Penetration Test Report

## Target: {state.target_ip}

| Item | Value |
|------|-------|
| Session ID | `{state.session_id}` |
| Start Time | {state.created_at} |
| End Time | {state.updated_at} |
| Status | **{state.phase.value.upper()}** |

---
"""

    def _build_summary(self, state: WorkflowState) -> str:
        """Build execution summary."""
        if not state.current_plan:
            return ""

        progress = state.current_plan.get_progress()

        return f"""## Execution Summary

| Metric | Value |
|--------|-------|
| Total Steps | {progress['total']} |
| Completed | {progress['completed']} |
| Failed | {progress['failed']} |
| Skipped | {progress['pending']} |
| Plan Version | v{state.current_plan.version} |

### Execution Plan

| # | Task Type | Description | Agent | Status |
|---|-----------|-------------|-------|--------|
""" + "\n".join([
            f"| {step.order} | {step.task_type.value.upper()} | {step.description} | {step.agent} | {'✅' if step.status.value == 'completed' else '❌' if step.status.value == 'failed' else '⏭️'} |"
            for step in sorted(state.current_plan.steps, key=lambda s: s.order)
        ]) + "\n\n---\n"

    def _build_agent_execution_details(
        self,
        state: WorkflowState,
        evidence_ledger: Any = None,
    ) -> str:
        """Build detailed agent execution section."""
        if not state.execution_history:
            return ""

        sections = ["## Agent Execution Details\n"]

        for i, execution in enumerate(state.execution_history, 1):
            result = execution.get("result", {})
            agent = result.get("agent", "unknown")
            success = result.get("success", False)
            result_data = result.get("result_data", {})
            evidence_ids = result.get("evidence_ids", [])
            observations = result.get("observations", [])

            # Get step info
            step_id = execution.get("step_id", "")
            step_info = None
            if state.current_plan:
                for step in state.current_plan.steps:
                    if step.step_id == step_id:
                        step_info = step
                        break

            # Agent header
            status_icon = "✅" if success else "❌"
            sections.append(f"### {i}. {agent.replace('_', ' ').title()} {status_icon}\n")

            # Step info
            if step_info:
                sections.append(f"**Task:** {step_info.description}\n")
                sections.append(f"**Task Type:** `{step_info.task_type.value}`\n")
                if step_info.parameters:
                    sections.append(f"**Parameters:**\n```json\n{self._format_dict(step_info.parameters)}\n```\n")

            # Execution timestamp
            sections.append(f"**Executed At:** {execution.get('timestamp', 'N/A')}\n")

            # Results
            sections.append("**Results:**\n")
            if result_data:
                # Handle raw output specially
                raw_output = result_data.get("raw", "")
                other_data = {k: v for k, v in result_data.items() if k != "raw"}

                if other_data:
                    sections.append("| Key | Value |\n|-----|-------|\n")
                    for key, value in other_data.items():
                        if isinstance(value, (list, dict)):
                            value = str(value)[:100]
                        sections.append(f"| {key} | {value} |\n")
                    sections.append("\n")

                if raw_output:
                    sections.append("**Raw Output:**\n```\n")
                    # Truncate if too long
                    if len(raw_output) > 2000:
                        sections.append(raw_output[:2000] + "\n... (truncated)\n")
                    else:
                        sections.append(raw_output + "\n")
                    sections.append("```\n")

            # Observations
            if observations:
                sections.append("**Observations:**\n")
                for obs in observations:
                    sections.append(f"- {obs}\n")
                sections.append("\n")

            # Evidence
            if evidence_ids:
                sections.append(f"**Evidence IDs:** `{'`, `'.join(evidence_ids)}`\n")

            sections.append("\n---\n")

        return "\n".join(sections)

    def _build_findings(self, state: WorkflowState) -> str:
        """Build findings section."""
        sections = ["## Findings\n"]

        if not state.findings:
            # Extract findings from execution results
            findings = self._extract_findings(state)
            if not findings:
                sections.append("No significant findings recorded.\n")
            else:
                for finding in findings:
                    sections.append(f"- {finding}\n")
        else:
            for finding in state.findings:
                if isinstance(finding, dict):
                    sections.append(f"### {finding.get('title', 'Finding')}\n")
                    sections.append(f"- Severity: {finding.get('severity', 'N/A')}\n")
                    sections.append(f"- Description: {finding.get('description', 'N/A')}\n")
                else:
                    sections.append(f"- {finding}\n")

        sections.append("\n---\n")
        return "\n".join(sections)

    def _extract_findings(self, state: WorkflowState) -> List[str]:
        """Extract findings from execution history."""
        findings = []

        for execution in state.execution_history:
            result = execution.get("result", {})
            result_data = result.get("result_data", {})
            agent = result.get("agent", "")

            # Extract port scan findings
            if agent == "recon_agent":
                open_ports = result_data.get("open_ports", 0)
                if open_ports > 0:
                    findings.append(f"Port Scan: {open_ports} open ports detected")

            # Extract vulnerability findings
            if agent == "enumeration_agent":
                cve_count = result_data.get("cve_count", 0)
                vulns = result_data.get("vulnerabilities_found", 0)
                if cve_count > 0:
                    findings.append(f"Vulnerability Scan: {cve_count} CVE references found")
                if vulns > 0:
                    findings.append(f"Vulnerability Scan: {vulns} potential vulnerabilities")

            # Extract exploitation findings
            if agent == "exploitation_agent":
                if result_data.get("exploitation_success"):
                    method = result_data.get("method", "Unknown method")
                    findings.append(f"Exploitation: Success via {method}")
                specific_findings = result_data.get("findings", [])
                for f in specific_findings:
                    findings.append(f"Exploitation: {f}")

        return findings

    def _build_evidence_list(self, state: WorkflowState) -> str:
        """Build evidence list section."""
        sections = ["## Evidence\n"]
        sections.append("| Evidence ID | Source | Timestamp |\n")
        sections.append("|-------------|--------|----------|\n")

        seen_evidence = set()
        for execution in state.execution_history:
            result = execution.get("result", {})
            evidence_ids = result.get("evidence_ids", [])
            agent = result.get("agent", "unknown")
            timestamp = execution.get("timestamp", "N/A")

            for eid in evidence_ids:
                if eid not in seen_evidence:
                    seen_evidence.add(eid)
                    sections.append(f"| `{eid}` | {agent} | {timestamp} |\n")

        sections.append("\n---\n")
        return "\n".join(sections)

    def _build_timeline(self, state: WorkflowState) -> str:
        """Build execution timeline."""
        sections = ["## Execution Timeline\n"]
        sections.append("```\n")

        for execution in state.execution_history:
            result = execution.get("result", {})
            agent = result.get("agent", "unknown")
            success = result.get("success", False)
            timestamp = execution.get("timestamp", "")

            # Extract time portion
            time_str = timestamp.split("T")[1][:8] if "T" in timestamp else timestamp

            status = "SUCCESS" if success else "FAILED"
            sections.append(f"[{time_str}] {agent}: {status}\n")

        sections.append("```\n\n---\n")
        return "\n".join(sections)

    def _build_footer(self, state: WorkflowState) -> str:
        """Build report footer."""
        return f"""## Session Information

- **Session Path:** `workspace/sessions/{state.session_id}/`
- **Report Generated:** {datetime.utcnow().isoformat()}Z

---

*Generated by PentestAgent Interactive Workflow*
"""

    def _format_dict(self, d: Dict[str, Any], indent: int = 2) -> str:
        """Format dictionary for display."""
        import json
        return json.dumps(d, indent=indent, ensure_ascii=False)

    # ============================================================
    # FR-8: OPTRS/OWASP-Style Professional Report
    # ============================================================

    def generate_professional_report(
        self,
        workflow_state: WorkflowState,
        test_plan: Optional[TestPlan] = None,
        findings: Optional[List[FindingCandidate]] = None,
        evidence_ledger: Optional["EvidenceLedger"] = None,
        organization_name: str = "Target Organization",
        assessor_name: str = "Security Assessment Team",
    ) -> str:
        """
        Generate a professional OPTRS/OWASP-style penetration test report.

        Args:
            workflow_state: Completed workflow state.
            test_plan: Optional test plan.
            findings: List of confirmed findings.
            evidence_ledger: Optional evidence ledger.
            organization_name: Name of the assessed organization.
            assessor_name: Name of the assessment team.

        Returns:
            Path to the generated report file.
        """
        target_ip = workflow_state.target_ip
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")

        # Build professional report
        report = self._build_professional_report(
            workflow_state,
            test_plan,
            findings or [],
            evidence_ledger,
            organization_name,
            assessor_name,
        )

        # Save report
        filename = f"PenetrationTest_Report_{target_ip.replace('.', '_')}_{timestamp}.md"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report)

        return filepath

    def _build_professional_report(
        self,
        state: WorkflowState,
        test_plan: Optional[TestPlan],
        findings: List[FindingCandidate],
        evidence_ledger: Optional["EvidenceLedger"],
        organization_name: str,
        assessor_name: str,
    ) -> str:
        """Build OPTRS/OWASP-style professional report."""
        sections = [
            self._build_professional_cover(state, organization_name, assessor_name),
            self._build_table_of_contents(),
            self._build_executive_summary(state, findings, test_plan),
            self._build_scope_and_methodology(state, test_plan),
            self._build_risk_rating_methodology(),
            self._build_findings_summary_table(findings),
            self._build_detailed_findings(findings, evidence_ledger),
            self._build_remediation_roadmap(findings),
            self._build_appendix_evidence(state, evidence_ledger),
            self._build_appendix_tools(),
            self._build_professional_footer(state, assessor_name),
        ]

        return "\n".join(sections)

    def _build_professional_cover(
        self,
        state: WorkflowState,
        organization_name: str,
        assessor_name: str,
    ) -> str:
        """Build professional report cover page."""
        return f"""# Penetration Test Report

## {organization_name}

---

| **Document Information** | |
|--------------------------|---|
| **Target** | `{state.target_ip}` |
| **Assessment Period** | {state.created_at[:10]} to {state.updated_at[:10]} |
| **Report Date** | {datetime.utcnow().strftime("%Y-%m-%d")} |
| **Assessor** | {assessor_name} |
| **Classification** | CONFIDENTIAL |
| **Version** | 1.0 |

---

> **DISCLAIMER:** This report contains sensitive security information and is intended
> solely for the authorized recipients. Unauthorized distribution or disclosure of this
> report may result in legal action. The findings in this report are based on the
> assessment conducted during the specified period and may not reflect the current
> security posture of the target system.

---

"""

    def _build_table_of_contents(self) -> str:
        """Build table of contents."""
        return """## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope and Methodology](#scope-and-methodology)
3. [Risk Rating Methodology](#risk-rating-methodology)
4. [Findings Summary](#findings-summary)
5. [Detailed Findings](#detailed-findings)
6. [Remediation Roadmap](#remediation-roadmap)
7. [Appendix A: Evidence](#appendix-a-evidence)
8. [Appendix B: Tools Used](#appendix-b-tools-used)

---

"""

    def _build_executive_summary(
        self,
        state: WorkflowState,
        findings: List[FindingCandidate],
        test_plan: Optional[TestPlan],
    ) -> str:
        """Build executive summary section."""
        # Count findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.severity.value.lower() if finding.severity else "info"
            if sev in severity_counts:
                severity_counts[sev] += 1

        total_findings = len(findings)
        critical_high = severity_counts["critical"] + severity_counts["high"]

        # Determine overall risk
        if severity_counts["critical"] > 0:
            overall_risk = "CRITICAL"
            risk_color = "🔴"
        elif severity_counts["high"] > 0:
            overall_risk = "HIGH"
            risk_color = "🟠"
        elif severity_counts["medium"] > 0:
            overall_risk = "MEDIUM"
            risk_color = "🟡"
        elif severity_counts["low"] > 0:
            overall_risk = "LOW"
            risk_color = "🟢"
        else:
            overall_risk = "INFORMATIONAL"
            risk_color = "🔵"

        # Build summary text
        summary_text = self._generate_executive_narrative(
            state, findings, severity_counts, test_plan
        )

        return f"""## Executive Summary

### Overall Risk Rating

{risk_color} **{overall_risk}**

### Findings Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | {severity_counts['critical']} |
| 🟠 High | {severity_counts['high']} |
| 🟡 Medium | {severity_counts['medium']} |
| 🟢 Low | {severity_counts['low']} |
| 🔵 Informational | {severity_counts['info']} |
| **Total** | **{total_findings}** |

### Summary

{summary_text}

### Key Recommendations

1. **Immediate Action Required:** Address all {severity_counts['critical']} critical and {severity_counts['high']} high severity findings within 7 days.
2. **Short-term (30 days):** Remediate medium severity findings and implement recommended security controls.
3. **Long-term (90 days):** Address low severity findings and establish continuous security monitoring.

---

"""

    def _generate_executive_narrative(
        self,
        state: WorkflowState,
        findings: List[FindingCandidate],
        severity_counts: Dict[str, int],
        test_plan: Optional[TestPlan],
    ) -> str:
        """Generate natural language executive narrative."""
        target = state.target_ip
        total = len(findings)
        critical_high = severity_counts["critical"] + severity_counts["high"]

        if total == 0:
            return (
                f"The penetration test of {target} was completed successfully. "
                "No significant vulnerabilities were identified during the assessment period. "
                "The target system demonstrates a mature security posture. "
                "However, continuous monitoring and regular security assessments are recommended."
            )

        narrative_parts = [
            f"A comprehensive penetration test was conducted against {target}. "
        ]

        if critical_high > 0:
            narrative_parts.append(
                f"The assessment identified **{critical_high} critical or high severity vulnerabilities** "
                "that require immediate attention. "
            )

        if severity_counts["critical"] > 0:
            narrative_parts.append(
                "Critical vulnerabilities discovered could potentially allow an attacker to "
                "gain unauthorized access to sensitive systems or data. "
            )

        if severity_counts["high"] > 0:
            narrative_parts.append(
                "High severity findings represent significant security risks that should be "
                "addressed as a priority. "
            )

        # Add exploitation success info if available
        exploitation_success = any(
            exec.get("result", {}).get("result_data", {}).get("exploitation_success")
            for exec in state.execution_history
        )
        if exploitation_success:
            narrative_parts.append(
                "**Important:** During the assessment, successful exploitation was achieved, "
                "demonstrating that identified vulnerabilities are actively exploitable. "
            )

        narrative_parts.append(
            "Detailed findings and remediation recommendations are provided in the sections below."
        )

        return "".join(narrative_parts)

    def _build_scope_and_methodology(
        self,
        state: WorkflowState,
        test_plan: Optional[TestPlan],
    ) -> str:
        """Build scope and methodology section."""
        scope_text = ""
        if test_plan:
            scope_text = f"""
**Scope Summary:** {test_plan.scope_summary}

**Target Description:** {test_plan.target_description}

**Primary Objective:** {test_plan.primary_objective}
"""
        else:
            scope_text = f"**Target:** {state.target_ip}"

        methodology = """
The assessment followed a structured methodology aligned with industry standards:

1. **Reconnaissance:** Passive and active information gathering to identify the target's attack surface.
2. **Enumeration:** Detailed service and application enumeration to identify potential entry points.
3. **Vulnerability Assessment:** Identification of known vulnerabilities using CVE/NVD databases.
4. **Exploitation:** Controlled exploitation to verify vulnerability impact (with authorization).
5. **Reporting:** Documentation of findings with CVSS scoring and remediation guidance.
"""

        constraints = ""
        if test_plan and test_plan.constraints:
            constraints = "\n**Constraints Applied:**\n"
            for c in test_plan.constraints:
                constraints += f"- {c}\n"

        return f"""## Scope and Methodology

### Scope

{scope_text}

### Methodology

{methodology}

{constraints}

---

"""

    def _build_risk_rating_methodology(self) -> str:
        """Build risk rating methodology section."""
        return """## Risk Rating Methodology

This assessment uses the Common Vulnerability Scoring System (CVSS) version 3.1 for
standardized severity ratings. The following table describes the severity levels:

| CVSS Score | Severity | Description |
|------------|----------|-------------|
| 9.0 - 10.0 | 🔴 Critical | Exploitation is straightforward and typically leads to full system compromise. Immediate remediation required. |
| 7.0 - 8.9 | 🟠 High | Exploitation may require specific conditions but can lead to significant impact. Remediate within 7 days. |
| 4.0 - 6.9 | 🟡 Medium | Exploitation requires moderate effort or specific prerequisites. Remediate within 30 days. |
| 0.1 - 3.9 | 🟢 Low | Limited impact or difficult to exploit. Remediate within 90 days. |
| 0.0 | 🔵 Informational | Best practice recommendations with no direct security impact. |

### CVSS Vector Components

| Component | Description |
|-----------|-------------|
| AV (Attack Vector) | Network (N), Adjacent (A), Local (L), Physical (P) |
| AC (Attack Complexity) | Low (L), High (H) |
| PR (Privileges Required) | None (N), Low (L), High (H) |
| UI (User Interaction) | None (N), Required (R) |
| S (Scope) | Unchanged (U), Changed (C) |
| C (Confidentiality) | None (N), Low (L), High (H) |
| I (Integrity) | None (N), Low (L), High (H) |
| A (Availability) | None (N), Low (L), High (H) |

---

"""

    def _build_findings_summary_table(
        self,
        findings: List[FindingCandidate],
    ) -> str:
        """Build findings summary table."""
        if not findings:
            return """## Findings Summary

No vulnerabilities were identified during the assessment.

---

"""

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(
                f.severity.value.lower() if f.severity else "info", 5
            ),
        )

        rows = []
        for i, finding in enumerate(sorted_findings, 1):
            sev = finding.severity.value if finding.severity else "Info"
            sev_icon = self._get_severity_icon(sev)
            cvss_display = finding.get_cvss_display() if hasattr(finding, 'get_cvss_display') else str(finding.cvss_score or "N/A")

            rows.append(
                f"| {i} | {finding.title} | {sev_icon} {sev} | {cvss_display} | {finding.affected_component or 'N/A'} |"
            )

        return f"""## Findings Summary

| # | Finding | Severity | CVSS | Affected Component |
|---|---------|----------|------|-------------------|
{chr(10).join(rows)}

---

"""

    def _get_severity_icon(self, severity: str) -> str:
        """Get severity icon."""
        icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }
        return icons.get(severity.lower(), "⚪")

    def _build_detailed_findings(
        self,
        findings: List[FindingCandidate],
        evidence_ledger: Optional["EvidenceLedger"],
    ) -> str:
        """Build detailed findings section."""
        if not findings:
            return """## Detailed Findings

No findings to report.

---

"""

        sections = ["## Detailed Findings\n"]

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(
                f.severity.value.lower() if f.severity else "info", 5
            ),
        )

        for i, finding in enumerate(sorted_findings, 1):
            sections.append(self._format_single_finding(i, finding, evidence_ledger))

        sections.append("\n---\n")
        return "\n".join(sections)

    def _format_single_finding(
        self,
        index: int,
        finding: FindingCandidate,
        evidence_ledger: Optional["EvidenceLedger"],
    ) -> str:
        """Format a single finding in OPTRS/OWASP style."""
        sev = finding.severity.value if finding.severity else "Info"
        sev_icon = self._get_severity_icon(sev)

        # CVSS display
        cvss_section = ""
        if hasattr(finding, 'cvss') and finding.cvss:
            cvss = finding.cvss
            cvss_section = f"""
| **CVSS Version** | {cvss.cvss.version.value if cvss.cvss else 'N/A'} |
| **CVSS Vector** | `{cvss.cvss.vector if cvss.cvss and cvss.cvss.vector else 'N/A'}` |
| **Base Score** | {cvss.cvss.base_score if cvss.cvss else 'N/A'} |
"""
        elif finding.cvss_score:
            cvss_section = f"""
| **CVSS Score** | {finding.cvss_score} |
"""

        # Evidence references
        evidence_section = ""
        if finding.evidence_ids:
            evidence_section = f"\n**Evidence:** `{'`, `'.join(finding.evidence_ids)}`\n"

        # Remediation
        remediation = finding.remediation if hasattr(finding, 'remediation') and finding.remediation else "Consult vendor documentation for specific remediation guidance."

        # References
        references = ""
        if hasattr(finding, 'references') and finding.references:
            references = "\n**References:**\n"
            for ref in finding.references[:5]:  # Limit to 5
                references += f"- {ref}\n"

        return f"""
### {index}. {finding.title}

{sev_icon} **Severity:** {sev.upper()}

| **Attribute** | **Value** |
|---------------|-----------|
| **Finding ID** | `{finding.finding_id}` |
| **Affected Component** | {finding.affected_component or 'N/A'} |
{cvss_section}

#### Description

{finding.description}

#### Impact

{finding.impact if hasattr(finding, 'impact') and finding.impact else 'Potential security impact depends on the exploitation scenario.'}

#### Reproduction Steps

{self._format_reproduction_steps(finding)}

#### Remediation

{remediation}
{evidence_section}
{references}
"""

    def _format_reproduction_steps(self, finding: FindingCandidate) -> str:
        """Format reproduction steps."""
        if hasattr(finding, 'reproduction_steps') and finding.reproduction_steps:
            steps = []
            for i, step in enumerate(finding.reproduction_steps, 1):
                steps.append(f"{i}. {step}")
            return "\n".join(steps)
        return "Detailed reproduction steps are documented in the associated evidence."

    def _build_remediation_roadmap(
        self,
        findings: List[FindingCandidate],
    ) -> str:
        """Build remediation roadmap section."""
        if not findings:
            return """## Remediation Roadmap

No remediation actions required.

---

"""

        # Group by priority
        immediate = []  # Critical & High
        short_term = []  # Medium
        long_term = []  # Low & Info

        for finding in findings:
            sev = finding.severity.value.lower() if finding.severity else "info"
            if sev in ["critical", "high"]:
                immediate.append(finding)
            elif sev == "medium":
                short_term.append(finding)
            else:
                long_term.append(finding)

        sections = ["## Remediation Roadmap\n"]

        if immediate:
            sections.append("### Immediate Priority (0-7 Days)\n")
            sections.append("| Finding | Severity | Recommended Action |\n")
            sections.append("|---------|----------|-------------------|\n")
            for f in immediate:
                action = f.remediation[:80] + "..." if hasattr(f, 'remediation') and f.remediation and len(f.remediation) > 80 else (f.remediation if hasattr(f, 'remediation') and f.remediation else "See detailed finding")
                sections.append(f"| {f.title} | {f.severity.value if f.severity else 'N/A'} | {action} |\n")
            sections.append("\n")

        if short_term:
            sections.append("### Short-Term Priority (8-30 Days)\n")
            sections.append("| Finding | Severity | Recommended Action |\n")
            sections.append("|---------|----------|-------------------|\n")
            for f in short_term:
                action = f.remediation[:80] + "..." if hasattr(f, 'remediation') and f.remediation and len(f.remediation) > 80 else (f.remediation if hasattr(f, 'remediation') and f.remediation else "See detailed finding")
                sections.append(f"| {f.title} | {f.severity.value if f.severity else 'N/A'} | {action} |\n")
            sections.append("\n")

        if long_term:
            sections.append("### Long-Term Priority (31-90 Days)\n")
            sections.append("| Finding | Severity | Recommended Action |\n")
            sections.append("|---------|----------|-------------------|\n")
            for f in long_term:
                action = f.remediation[:80] + "..." if hasattr(f, 'remediation') and f.remediation and len(f.remediation) > 80 else (f.remediation if hasattr(f, 'remediation') and f.remediation else "See detailed finding")
                sections.append(f"| {f.title} | {f.severity.value if f.severity else 'N/A'} | {action} |\n")
            sections.append("\n")

        sections.append("---\n")
        return "".join(sections)

    def _build_appendix_evidence(
        self,
        state: WorkflowState,
        evidence_ledger: Optional["EvidenceLedger"],
    ) -> str:
        """Build appendix with evidence summary."""
        sections = ["## Appendix A: Evidence\n"]
        sections.append("| Evidence ID | Source | Type | SHA256 |\n")
        sections.append("|-------------|--------|------|--------|\n")

        seen_evidence = set()
        for execution in state.execution_history:
            result = execution.get("result", {})
            evidence_ids = result.get("evidence_ids", [])
            agent = result.get("agent", "unknown")

            for eid in evidence_ids:
                if eid not in seen_evidence:
                    seen_evidence.add(eid)
                    # Get SHA from ledger if available
                    sha256 = "N/A"
                    if evidence_ledger:
                        meta = evidence_ledger.get_evidence_meta(eid)
                        if meta:
                            sha256 = meta.get("sha256", "N/A")[:16] + "..."
                    sections.append(f"| `{eid}` | {agent} | raw | `{sha256}` |\n")

        if not seen_evidence:
            sections.append("| - | - | - | - |\n")

        sections.append("\n---\n")
        return "".join(sections)

    def _build_appendix_tools(self) -> str:
        """Build appendix with tools used."""
        return """## Appendix B: Tools Used

| Tool | Purpose | Version |
|------|---------|---------|
| Nmap | Network scanning and service detection | Latest |
| Nuclei | Vulnerability scanning | Latest |
| Nikto | Web server scanner | Latest |
| Feroxbuster | Directory enumeration | Latest |
| httpx | HTTP probing | Latest |
| subfinder | Subdomain discovery | Latest |
| katana | Web crawling | Latest |
| wafw00f | WAF detection | Latest |

*All tools were used within the authorized scope and in accordance with the engagement rules.*

---

"""

    def _build_professional_footer(
        self,
        state: WorkflowState,
        assessor_name: str,
    ) -> str:
        """Build professional report footer."""
        return f"""## Document Control

| Version | Date | Author | Description |
|---------|------|--------|-------------|
| 1.0 | {datetime.utcnow().strftime("%Y-%m-%d")} | {assessor_name} | Initial report |

---

**Session Information:**
- Session ID: `{state.session_id}`
- Session Path: `workspace/sessions/{state.session_id}/`
- Report Generated: {datetime.utcnow().isoformat()}Z

---

*This report was generated by PentestAgent. All findings should be validated by qualified security professionals before implementing remediation actions.*

---
**END OF REPORT**
"""
