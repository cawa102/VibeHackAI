"""
Planner Agent for PentestAgent.

Identifies vulnerability candidates, evaluates feasibility,
and creates execution plans for exploitation.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .base_agent import (
    BaseAgent,
    AgentConfig,
    AgentContext,
    AgentOutput,
    AgentType,
)
from ..mcp_adapters.snyk_adapter import SnykAdapter
from ..mcp_adapters.cve_adapter import CVEAdapter
from ..mcp_adapters.github_adapter import GitHubAdapter
from ..mcp_adapters.base_adapter import MCPResult
from ..patch.patch import Patch, PatchOperation
from ..patch.operations import OperationType


@dataclass
class VulnCandidate:
    """Vulnerability candidate identified by the planner."""
    vuln_id: str
    cve_id: Optional[str]
    title: str
    description: str
    severity: str  # critical, high, medium, low
    cvss_score: float
    affected_component: str
    affected_version: str
    confidence: float  # 0.0 to 1.0
    evidence_ids: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    exploitability: str = "unknown"  # functional, poc, theoretical, unknown

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "affected_component": self.affected_component,
            "affected_version": self.affected_version,
            "confidence": self.confidence,
            "evidence_ids": self.evidence_ids,
            "prerequisites": self.prerequisites,
            "exploitability": self.exploitability,
        }


@dataclass
class ExploitCandidate:
    """Exploit candidate for a vulnerability."""
    exploit_id: str
    vuln_candidate_id: str
    source: str  # github, exploit-db, metasploit
    name: str
    url: str
    reliability_score: float  # 0.0 to 1.0
    language: Optional[str] = None
    requirements: List[str] = field(default_factory=list)
    verified: bool = False
    last_updated: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exploit_id": self.exploit_id,
            "vuln_candidate_id": self.vuln_candidate_id,
            "source": self.source,
            "name": self.name,
            "url": self.url,
            "reliability_score": self.reliability_score,
            "language": self.language,
            "requirements": self.requirements,
            "verified": self.verified,
            "last_updated": self.last_updated,
        }


@dataclass
class ExecutionStep:
    """A step in the execution plan."""
    step_id: str
    order: int
    action: str
    description: str
    target: str
    exploit_id: Optional[str] = None
    requires_approval: bool = False
    rollback_action: Optional[str] = None
    expected_outcome: Optional[str] = None
    timeout_seconds: int = 300

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "order": self.order,
            "action": self.action,
            "description": self.description,
            "target": self.target,
            "exploit_id": self.exploit_id,
            "requires_approval": self.requires_approval,
            "rollback_action": self.rollback_action,
            "expected_outcome": self.expected_outcome,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class ExecutionPlan:
    """Execution plan for exploitation."""
    plan_id: str
    vuln_candidates: List[str]  # vuln_candidate_ids
    exploit_candidates: List[str]  # exploit_candidate_ids
    steps: List[ExecutionStep]
    priority_score: float
    estimated_success_rate: float
    risk_level: str  # low, medium, high, critical
    requires_approval: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "vuln_candidates": self.vuln_candidates,
            "exploit_candidates": self.exploit_candidates,
            "steps": [s.to_dict() for s in self.steps],
            "priority_score": self.priority_score,
            "estimated_success_rate": self.estimated_success_rate,
            "risk_level": self.risk_level,
            "requires_approval": self.requires_approval,
        }


class PlannerAgent(BaseAgent):
    """
    Planner Agent.

    Responsibilities:
    - Vulnerability candidate identification from target profile
    - CVE/Snyk database lookups
    - Exploit/PoC search (GitHub)
    - Feasibility evaluation
    - Execution plan creation
    """

    # Dangerous operations requiring approval
    DANGEROUS_OPERATIONS = [
        "exploit_rce",
        "exploit_sqli",
        "exploit_auth_bypass",
        "file_write",
        "privilege_escalation",
    ]

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        snyk_adapter: Optional[SnykAdapter] = None,
        cve_adapter: Optional[CVEAdapter] = None,
        github_adapter: Optional[GitHubAdapter] = None,
        mock_mode: bool = False,
    ):
        """
        Initialize Planner Agent.

        Args:
            config: Agent configuration.
            snyk_adapter: Snyk MCP adapter.
            cve_adapter: CVE Research MCP adapter.
            github_adapter: GitHub MCP adapter.
            mock_mode: If True, use mock adapters.
        """
        if config is None:
            config = AgentConfig(
                agent_type=AgentType.PLANNER,
                timeout_seconds=600,  # 10 minutes
            )

        super().__init__(config)

        # Initialize adapters
        self.snyk = snyk_adapter or SnykAdapter(mock_mode=mock_mode)
        self.cve = cve_adapter or CVEAdapter(mock_mode=mock_mode)
        self.github = github_adapter or GitHubAdapter(mock_mode=mock_mode)

        # Results storage
        self._evidences: List[Dict[str, Any]] = []
        self._observations: List[Dict[str, Any]] = []
        self._vuln_candidates: List[VulnCandidate] = []
        self._exploit_candidates: List[ExploitCandidate] = []
        self._execution_plan: Optional[ExecutionPlan] = None

    def _execute(self, context: AgentContext) -> AgentOutput:
        """
        Execute planning.

        Args:
            context: Agent context.

        Returns:
            AgentOutput with results.
        """
        self._evidences = []
        self._observations = []
        self._vuln_candidates = []
        self._exploit_candidates = []
        self._execution_plan = None

        # Extract tech stack from target profile
        tech_stack = self._extract_tech_stack(context)
        if not tech_stack:
            return self._create_error_output(
                context, "No technology stack found in target profile"
            )

        self._record_decision(
            "tech_stack_analysis",
            f"Identified {len(tech_stack)} technologies",
            f"Extracted technologies from target profile for vulnerability analysis",
            inputs={"target_profile": context.target_profile},
            outputs={"tech_stack": tech_stack},
        )

        # Phase 1: Vulnerability lookup
        self._lookup_vulnerabilities(tech_stack)

        if not self._vuln_candidates:
            self._record_decision(
                "no_vulns_found",
                "No vulnerability candidates found",
                "Vulnerability databases returned no matches for the identified technologies",
            )
            # Still return success with empty results
            operations = self._generate_operations()
            patch = self._create_patch(context, operations)
            return self._create_success_output(context, patch, {
                "vuln_candidates_found": 0,
                "exploit_candidates_found": 0,
                "execution_plan_created": False,
            })

        # Phase 2: Feasibility evaluation
        self._evaluate_feasibility(context)

        # Phase 3: Exploit search
        self._search_exploits()

        # Phase 4: Create execution plan
        self._create_execution_plan(context)

        # Generate patch
        operations = self._generate_operations()
        patch = self._create_patch(context, operations)

        # Create phase result
        phase_result = {
            "vuln_candidates_found": len(self._vuln_candidates),
            "exploit_candidates_found": len(self._exploit_candidates),
            "execution_plan_created": self._execution_plan is not None,
            "high_severity_vulns": sum(
                1 for v in self._vuln_candidates if v.severity in ["critical", "high"]
            ),
            "verified_exploits": sum(
                1 for e in self._exploit_candidates if e.verified
            ),
        }

        return self._create_success_output(context, patch, phase_result)

    def _extract_tech_stack(
        self, context: AgentContext
    ) -> List[Dict[str, Any]]:
        """
        Extract technology stack from target profile.

        Args:
            context: Agent context.

        Returns:
            List of technology entries with name, version, type.
        """
        tech_stack = []
        target_profile = context.target_profile or {}

        # Check for direct technologies
        for tech_name, tech_info in target_profile.get("technologies", {}).items():
            if isinstance(tech_info, dict):
                tech_stack.append({
                    "name": tech_name,
                    "version": tech_info.get("version"),
                    "type": tech_info.get("type", "unknown"),
                })
            else:
                tech_stack.append({
                    "name": tech_name,
                    "version": str(tech_info) if tech_info else None,
                    "type": "unknown",
                })

        # Check for services in targets
        for target_id, target_info in target_profile.get("targets", {}).items():
            # Extract from ports/services
            for port_info in target_info.get("ports", []):
                if isinstance(port_info, dict):
                    product = port_info.get("product") or port_info.get("service")
                    if product:
                        tech_stack.append({
                            "name": product,
                            "version": port_info.get("version"),
                            "type": "service",
                            "port": port_info.get("port"),
                        })

        # Check observations for technology detection
        for obs in context.observations:
            if obs.get("type") == "technology_detection":
                for tech_name, tech_info in obs.get("data", {}).get("technologies", {}).items():
                    if isinstance(tech_info, dict):
                        tech_stack.append({
                            "name": tech_name,
                            "version": tech_info.get("version"),
                            "type": tech_info.get("type", "framework"),
                        })

        # Deduplicate
        seen = set()
        unique_stack = []
        for tech in tech_stack:
            key = (tech["name"].lower(), tech.get("version", ""))
            if key not in seen:
                seen.add(key)
                unique_stack.append(tech)

        return unique_stack

    def _lookup_vulnerabilities(
        self, tech_stack: List[Dict[str, Any]]
    ) -> None:
        """
        Lookup vulnerabilities for the technology stack.

        Args:
            tech_stack: List of technologies to check.
        """
        for tech in tech_stack:
            name = tech["name"]
            version = tech.get("version")

            # Search via Snyk
            snyk_result = self.snyk.search_vulnerabilities(name, version)
            if snyk_result.success:
                self._add_evidence(snyk_result)
                self._process_snyk_vulns(tech, snyk_result.data)

            # Search via CVE
            cve_result = self.cve.search_by_product(name, version)
            if cve_result.success:
                self._add_evidence(cve_result)
                self._process_cve_vulns(tech, cve_result.data)

    def _process_snyk_vulns(
        self,
        tech: Dict[str, Any],
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Process Snyk vulnerability results."""
        if not data:
            return

        for vuln in data.get("vulnerabilities", []):
            candidate = VulnCandidate(
                vuln_id=f"vuln-{uuid.uuid4().hex[:8]}",
                cve_id=vuln.get("cve"),
                title=vuln.get("title", "Unknown"),
                description=vuln.get("description", ""),
                severity=vuln.get("severity", "unknown").lower(),
                cvss_score=vuln.get("cvss_score", 0.0),
                affected_component=tech["name"],
                affected_version=tech.get("version", "unknown"),
                confidence=0.8,  # Snyk is reliable
                evidence_ids=[],
                exploitability=self._assess_exploitability(vuln),
            )
            self._vuln_candidates.append(candidate)

            self._add_observation(
                "vuln_identified",
                f"Identified vulnerability: {candidate.title}",
                candidate.to_dict(),
            )

    def _process_cve_vulns(
        self,
        tech: Dict[str, Any],
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Process CVE vulnerability results."""
        if not data:
            return

        for cve in data.get("cves", []):
            # Check if already added from Snyk
            cve_id = cve.get("cve_id")
            if any(v.cve_id == cve_id for v in self._vuln_candidates):
                continue

            candidate = VulnCandidate(
                vuln_id=f"vuln-{uuid.uuid4().hex[:8]}",
                cve_id=cve_id,
                title=cve.get("title", "Unknown"),
                description=cve.get("description", ""),
                severity=cve.get("severity", "unknown").lower(),
                cvss_score=cve.get("cvss_score", 0.0),
                affected_component=tech["name"],
                affected_version=tech.get("version", "unknown"),
                confidence=0.7,  # CVE data may need version verification
                evidence_ids=[],
            )
            self._vuln_candidates.append(candidate)

            self._add_observation(
                "vuln_identified",
                f"Identified CVE: {cve_id}",
                candidate.to_dict(),
            )

    def _assess_exploitability(
        self, vuln_data: Dict[str, Any]
    ) -> str:
        """Assess exploitability of a vulnerability."""
        if vuln_data.get("exploit_available"):
            if vuln_data.get("exploit_maturity") == "high":
                return "functional"
            return "poc"
        return "theoretical"

    def _evaluate_feasibility(self, context: AgentContext) -> None:
        """
        Evaluate feasibility of vulnerability exploitation.

        Args:
            context: Agent context.
        """
        target_profile = context.target_profile or {}

        for vuln in self._vuln_candidates:
            # Version check
            version_match = self._check_version_match(
                vuln.affected_version,
                vuln.affected_component,
                target_profile,
            )

            # Prerequisites check
            prereqs = self._check_prerequisites(vuln, context)

            # Adjust confidence based on checks
            if version_match:
                vuln.confidence = min(1.0, vuln.confidence + 0.1)
            else:
                vuln.confidence = max(0.0, vuln.confidence - 0.2)

            vuln.prerequisites = prereqs

            self._record_decision(
                "feasibility_evaluation",
                f"Evaluated {vuln.cve_id or vuln.vuln_id}",
                f"Version match: {version_match}, Prerequisites: {len(prereqs)}",
                inputs={"vuln_id": vuln.vuln_id},
                outputs={"confidence": vuln.confidence, "prerequisites": prereqs},
            )

    def _check_version_match(
        self,
        vuln_version: str,
        component: str,
        target_profile: Dict[str, Any],
    ) -> bool:
        """Check if vulnerability version matches target."""
        # Simplified version matching
        # In real implementation, would use proper version comparison
        if not vuln_version or vuln_version == "unknown":
            return True  # Can't verify, assume possible

        # Check technologies
        for tech_name, tech_info in target_profile.get("technologies", {}).items():
            if tech_name.lower() == component.lower():
                if isinstance(tech_info, dict):
                    target_version = tech_info.get("version")
                else:
                    target_version = str(tech_info)
                if target_version:
                    return self._version_in_range(target_version, vuln_version)

        return True  # Can't verify, assume possible

    def _version_in_range(
        self, target_version: str, vuln_version: str
    ) -> bool:
        """Check if target version is in vulnerable range."""
        # Simplified check - in real implementation use proper semver
        try:
            # Extract version numbers
            target_nums = [int(x) for x in re.findall(r'\d+', target_version)[:3]]
            vuln_nums = [int(x) for x in re.findall(r'\d+', vuln_version)[:3]]

            if not target_nums or not vuln_nums:
                return True

            # Simple comparison
            return target_nums <= vuln_nums
        except (ValueError, IndexError):
            return True  # Can't parse, assume possible

    def _check_prerequisites(
        self,
        vuln: VulnCandidate,
        context: AgentContext,
    ) -> List[str]:
        """Check prerequisites for exploitation."""
        prereqs = []

        # Check if authentication is required
        if vuln.severity == "critical" and vuln.cvss_score >= 9.0:
            # High severity often requires no auth
            pass
        elif "auth" in vuln.title.lower() or "authentication" in vuln.description.lower():
            prereqs.append("authentication_required")

        # Check network access
        target_profile = context.target_profile or {}
        if not target_profile.get("targets"):
            prereqs.append("network_access_required")

        return prereqs

    def _search_exploits(self) -> None:
        """Search for exploits for identified vulnerabilities."""
        for vuln in self._vuln_candidates:
            if not vuln.cve_id:
                continue

            # Search GitHub for PoCs
            poc_result = self.github.search_pocs_for_cve(vuln.cve_id)
            if poc_result.success:
                self._add_evidence(poc_result)
                self._process_pocs(vuln, poc_result.data)

            # Get exploit info from CVE database
            exploit_result = self.cve.get_exploit_info(vuln.cve_id)
            if exploit_result.success:
                self._add_evidence(exploit_result)
                self._update_exploitability(vuln, exploit_result.data)

    def _process_pocs(
        self,
        vuln: VulnCandidate,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Process PoC search results."""
        if not data:
            return

        for poc in data.get("pocs", []):
            candidate = ExploitCandidate(
                exploit_id=f"exploit-{uuid.uuid4().hex[:8]}",
                vuln_candidate_id=vuln.vuln_id,
                source="github",
                name=poc.get("repository", "Unknown"),
                url=poc.get("url", ""),
                reliability_score=poc.get("reliability_score", 0.5),
                language=poc.get("language"),
                verified=poc.get("verified", False),
                last_updated=poc.get("last_updated"),
            )
            self._exploit_candidates.append(candidate)

            self._add_observation(
                "exploit_found",
                f"Found PoC for {vuln.cve_id}: {candidate.name}",
                candidate.to_dict(),
            )

    def _update_exploitability(
        self,
        vuln: VulnCandidate,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Update vulnerability exploitability based on exploit info."""
        if not data:
            return

        if data.get("exploit_available"):
            maturity = data.get("exploit_maturity", "unknown")
            if maturity == "functional":
                vuln.exploitability = "functional"
            elif maturity in ["poc", "proof-of-concept"]:
                vuln.exploitability = "poc"

            if data.get("in_the_wild"):
                vuln.confidence = min(1.0, vuln.confidence + 0.1)

    def _create_execution_plan(self, context: AgentContext) -> None:
        """Create execution plan for exploitation."""
        if not self._vuln_candidates:
            return

        # Sort vulnerabilities by priority
        sorted_vulns = sorted(
            self._vuln_candidates,
            key=lambda v: (
                self._severity_to_score(v.severity),
                v.cvss_score,
                v.confidence,
            ),
            reverse=True,
        )

        # Select top candidates
        top_vulns = sorted_vulns[:3]

        # Get related exploits
        related_exploits = [
            e for e in self._exploit_candidates
            if e.vuln_candidate_id in [v.vuln_id for v in top_vulns]
        ]

        # Create steps
        steps = []
        order = 1

        for vuln in top_vulns:
            vuln_exploits = [
                e for e in related_exploits
                if e.vuln_candidate_id == vuln.vuln_id
            ]

            # Verification step
            steps.append(ExecutionStep(
                step_id=f"step-{uuid.uuid4().hex[:8]}",
                order=order,
                action="verify_vulnerability",
                description=f"Verify {vuln.cve_id or vuln.title} is exploitable",
                target=vuln.affected_component,
                requires_approval=False,
                expected_outcome="vulnerability_confirmed",
            ))
            order += 1

            # Exploitation step
            if vuln_exploits:
                best_exploit = max(vuln_exploits, key=lambda e: e.reliability_score)
                is_dangerous = self._is_dangerous_operation(vuln)

                steps.append(ExecutionStep(
                    step_id=f"step-{uuid.uuid4().hex[:8]}",
                    order=order,
                    action="execute_exploit",
                    description=f"Execute exploit for {vuln.cve_id or vuln.title}",
                    target=vuln.affected_component,
                    exploit_id=best_exploit.exploit_id,
                    requires_approval=is_dangerous,
                    rollback_action="terminate_session" if is_dangerous else None,
                    expected_outcome="exploitation_success",
                ))
                order += 1

        # Calculate plan metrics
        avg_confidence = sum(v.confidence for v in top_vulns) / len(top_vulns)
        has_verified_exploits = any(e.verified for e in related_exploits)
        max_severity = max(self._severity_to_score(v.severity) for v in top_vulns)

        risk_level = "critical" if max_severity >= 4 else \
                     "high" if max_severity >= 3 else \
                     "medium" if max_severity >= 2 else "low"

        self._execution_plan = ExecutionPlan(
            plan_id=f"plan-{uuid.uuid4().hex[:8]}",
            vuln_candidates=[v.vuln_id for v in top_vulns],
            exploit_candidates=[e.exploit_id for e in related_exploits],
            steps=steps,
            priority_score=max_severity * avg_confidence,
            estimated_success_rate=avg_confidence * (0.9 if has_verified_exploits else 0.6),
            risk_level=risk_level,
            requires_approval=any(s.requires_approval for s in steps),
        )

        self._record_decision(
            "execution_plan_created",
            f"Created plan with {len(steps)} steps",
            f"Priority: {self._execution_plan.priority_score:.2f}, "
            f"Success rate: {self._execution_plan.estimated_success_rate:.2f}",
            outputs=self._execution_plan.to_dict(),
        )

    def _severity_to_score(self, severity: str) -> int:
        """Convert severity to numeric score."""
        return {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }.get(severity.lower(), 0)

    def _is_dangerous_operation(self, vuln: VulnCandidate) -> bool:
        """Check if exploitation is a dangerous operation."""
        dangerous_keywords = [
            "rce", "remote code execution",
            "sql injection", "sqli",
            "authentication bypass",
            "privilege escalation",
            "file write", "arbitrary write",
        ]
        title_lower = vuln.title.lower()
        desc_lower = vuln.description.lower()

        return any(
            kw in title_lower or kw in desc_lower
            for kw in dangerous_keywords
        )

    def _add_evidence(self, result: MCPResult) -> None:
        """Add evidence from MCP result."""
        self._evidences.append(result.to_evidence())

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
        """Generate patch operations from collected data."""
        operations = []

        # Add evidence operations
        for evidence in self._evidences:
            operations.append(PatchOperation(
                op=OperationType.ADD_EVIDENCE,
                target="evidence",
                payload=evidence,
            ))

        # Add observation operations
        for observation in self._observations:
            operations.append(PatchOperation(
                op=OperationType.ADD_OBSERVATION,
                target="observations",
                payload=observation,
            ))

        # Add vulnerability candidates
        for vuln in self._vuln_candidates:
            operations.append(PatchOperation(
                op=OperationType.ADD_VULN_CANDIDATE,
                target="vuln_candidates",
                payload=vuln.to_dict(),
            ))

        # Add exploit candidates
        for exploit in self._exploit_candidates:
            operations.append(PatchOperation(
                op=OperationType.ADD_EXPLOIT_CANDIDATE,
                target="exploit_candidates",
                payload=exploit.to_dict(),
            ))

        # Add execution plan
        if self._execution_plan:
            operations.append(PatchOperation(
                op=OperationType.PROPOSE_EXECUTION_PLAN,
                target="execution_plan",
                payload=self._execution_plan.to_dict(),
                requires_approval=self._execution_plan.requires_approval,
            ))

        return operations

    def _should_skip(self, context: AgentContext) -> Optional[str]:
        """Check if planning should be skipped."""
        # Check if we already have an execution plan
        target_profile = context.target_profile or {}

        if target_profile.get("execution_plan"):
            plan = target_profile["execution_plan"]
            if plan.get("steps") and len(plan["steps"]) > 0:
                return "Execution plan already exists"

        return None
