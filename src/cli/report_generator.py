"""
Report Generator for PentestAgent.

Generates markdown reports from workflow execution results.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..orchestrator.workflow import WorkflowState, ExecutionPlan, TaskType


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
