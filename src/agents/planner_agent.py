"""
Planner Agent for PentestAgent.

Identifies vulnerability candidates, evaluates feasibility,
and creates execution plans for exploitation.

Enhanced for FR-6: Planner manages TestPlan as single source of truth.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

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
from ..schemas.test_plan import (
    TestPlan,
    PhaseObjective,
    PhaseStatus,
    PlanChangeType,
    PlanChangeEntry,
    OpenQuestion,
    TestPlanRisk,
    create_initial_test_plan,
)
from ..schemas.phase_brief import (
    PhaseBrief,
    PhaseType,
    RiskLevel,
    PlannedAction,
    SafetyConstraint,
)
from ..schemas.cvss import CVSS, CVSSVersion, CVSSSeverity, CVSSWithStatus, CVSSAssessmentStatus


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
    # FR-7: Enhanced CVSS support
    cvss_version: Optional[str] = None  # "3.0", "3.1", "4.0"
    cvss_vector: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
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
        # Include CVSS details if available
        if self.cvss_version or self.cvss_vector:
            result["cvss"] = {
                "version": self.cvss_version,
                "vector": self.cvss_vector,
                "base_score": self.cvss_score,
            }
        return result

    def get_cvss_object(self) -> Optional[CVSS]:
        """Get CVSS object for this vulnerability."""
        if not self.cvss_score:
            return None
        version = CVSSVersion.V3_1
        if self.cvss_version:
            version_map = {
                "3.0": CVSSVersion.V3_0,
                "3.1": CVSSVersion.V3_1,
                "4.0": CVSSVersion.V4_0,
            }
            version = version_map.get(self.cvss_version, CVSSVersion.V3_1)
        return CVSS(
            version=version,
            vector=self.cvss_vector,
            base_score=self.cvss_score,
        )


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

    # ============================================================
    # FR-6: TestPlan Management (Single Source of Truth)
    # ============================================================

    def create_test_plan(
        self,
        session_id: str,
        scope: Dict[str, Any],
        target_profile: Optional[Dict[str, Any]] = None,
    ) -> TestPlan:
        """
        Create a new TestPlan for a session.

        This is the single source of truth for the penetration test.

        Args:
            session_id: Session identifier.
            scope: Scope definition.
            target_profile: Optional target profile.

        Returns:
            Initialized TestPlan.
        """
        # Build scope summary
        scope_summary = self._build_scope_summary(scope)

        # Build target description
        target_description = self._build_target_description(scope, target_profile)

        # Create the plan
        test_plan = create_initial_test_plan(
            session_id=session_id,
            target_description=target_description,
            scope_summary=scope_summary,
        )

        # Add scope-specific constraints
        if scope.get("proof_of_access_policy"):
            poa = scope["proof_of_access_policy"]
            test_plan.constraints.append(
                f"Proof-of-Access Policy: Max {poa.get('max_bytes', 4096)} bytes per file, "
                f"max {poa.get('max_files', 5)} files total"
            )

        # Add scope-specific risks
        test_plan.risks.append(TestPlanRisk(
            description="Target may have active security monitoring",
            likelihood="medium",
            impact="medium",
            mitigation="Rate-limit scans and use non-invasive techniques",
        ))

        self._test_plan = test_plan
        return test_plan

    def _build_scope_summary(self, scope: Dict[str, Any]) -> str:
        """Build human-readable scope summary."""
        parts = []

        targets = scope.get("targets", [])
        if targets:
            target_types = {}
            for t in targets:
                t_type = t.get("type", "unknown")
                if t_type not in target_types:
                    target_types[t_type] = []
                target_types[t_type].append(t.get("value", ""))

            for t_type, values in target_types.items():
                if len(values) <= 3:
                    parts.append(f"{t_type.upper()}: {', '.join(values)}")
                else:
                    parts.append(f"{t_type.upper()}: {len(values)} targets")

        allowed_ops = scope.get("allowed_operations", [])
        if allowed_ops:
            parts.append(f"Allowed operations: {', '.join(allowed_ops)}")

        excluded = scope.get("excluded_targets", [])
        if excluded:
            parts.append(f"Excluded: {len(excluded)} targets")

        return "; ".join(parts) if parts else "Scope not fully defined"

    def _build_target_description(
        self,
        scope: Dict[str, Any],
        target_profile: Optional[Dict[str, Any]],
    ) -> str:
        """Build human-readable target description."""
        targets = scope.get("targets", [])
        if not targets:
            return "Target(s) to be identified"

        descriptions = []
        for target in targets[:3]:  # Limit to first 3
            t_type = target.get("type", "")
            t_value = target.get("value", "")
            descriptions.append(f"{t_type}: {t_value}")

        if len(targets) > 3:
            descriptions.append(f"... and {len(targets) - 3} more")

        if target_profile:
            tech_count = len(target_profile.get("technologies", {}))
            if tech_count:
                descriptions.append(f"{tech_count} technologies identified")

        return ", ".join(descriptions)

    def update_test_plan_after_phase(
        self,
        test_plan: TestPlan,
        completed_phase: PhaseType,
        phase_result: Dict[str, Any],
        findings_summary: Optional[str] = None,
    ) -> TestPlan:
        """
        Update TestPlan after a phase completes.

        Args:
            test_plan: Current test plan.
            completed_phase: The phase that just completed.
            phase_result: Results from the phase.
            findings_summary: Optional summary of findings.

        Returns:
            Updated TestPlan.
        """
        # Update phase status
        test_plan.update_phase_status(
            phase=completed_phase,
            status=PhaseStatus.COMPLETED,
            changed_by="planner_agent",
            notes=findings_summary,
        )

        # Analyze results and potentially adjust priorities
        self._adjust_plan_based_on_results(test_plan, completed_phase, phase_result)

        # Update current phase
        next_phase = test_plan.get_next_phase()
        if next_phase:
            test_plan.current_phase = next_phase.phase
            test_plan.update_phase_status(
                phase=next_phase.phase,
                status=PhaseStatus.IN_PROGRESS,
                changed_by="planner_agent",
            )

        return test_plan

    def _adjust_plan_based_on_results(
        self,
        test_plan: TestPlan,
        phase: PhaseType,
        result: Dict[str, Any],
    ) -> None:
        """Adjust test plan based on phase results."""
        # If critical vulnerabilities found, prioritize exploitation
        if phase == PhaseType.VULNERABILITY_ASSESSMENT:
            high_severity = result.get("high_severity_vulns", 0)
            if high_severity > 0:
                test_plan.add_change(
                    change_type=PlanChangeType.FINDING_IMPACT,
                    summary=f"Found {high_severity} high/critical severity vulnerabilities",
                    reason="Critical findings require prioritized exploitation",
                    changed_by="planner_agent",
                )
                test_plan.overall_risk_level = RiskLevel.HIGH

        # If no vulnerabilities found, add question
        if phase == PhaseType.VULNERABILITY_ASSESSMENT:
            if result.get("vuln_candidates_found", 0) == 0:
                test_plan.open_questions.append(OpenQuestion(
                    question="No vulnerabilities identified - should we expand scan scope?",
                    context="Vulnerability assessment returned no candidates",
                    priority="high",
                ))

    def generate_phase_brief(
        self,
        test_plan: TestPlan,
        phase: PhaseType,
        previous_phase_result: Optional[Dict[str, Any]] = None,
    ) -> PhaseBrief:
        """
        Generate a PhaseBrief for human approval.

        This is for FR-2: Natural language summary only, NO commands.

        Args:
            test_plan: Current test plan.
            phase: Phase to generate brief for.
            previous_phase_result: Results from previous phase.

        Returns:
            PhaseBrief for human approval.
        """
        # Find phase objective
        phase_objective = None
        for obj in test_plan.phase_sequence:
            if obj.phase == phase:
                phase_objective = obj
                break

        objective = phase_objective.objective if phase_objective else f"Execute {phase.value}"

        # Generate rationale
        rationale = self._generate_phase_rationale(phase, previous_phase_result)

        # Generate planned actions (natural language only)
        planned_actions = self._generate_planned_actions_for_phase(phase, test_plan)

        # Generate safety constraints
        safety_constraints = self._generate_safety_constraints_for_phase(phase, test_plan)

        # Determine risk level
        risk_level = self._determine_phase_risk_level(phase, test_plan)

        return PhaseBrief(
            phase=phase,
            title=f"{phase.value.replace('_', ' ').title()} Phase",
            objective=objective,
            rationale=rationale,
            planned_actions=planned_actions,
            risk_notes=self._generate_phase_risk_notes(phase, test_plan),
            safety_constraints=safety_constraints,
            expected_outcomes=self._generate_phase_expected_outcomes(phase),
            overall_risk_level=risk_level,
            requires_phase_approval=True,
        )

    def _generate_phase_rationale(
        self,
        phase: PhaseType,
        previous_result: Optional[Dict[str, Any]],
    ) -> str:
        """Generate natural language rationale for a phase."""
        if previous_result is None:
            if phase == PhaseType.RECONNAISSANCE:
                return "Initial information gathering to understand the target's attack surface and infrastructure."
            return f"Starting {phase.value} as part of the planned test sequence."

        rationales = {
            PhaseType.ENUMERATION: (
                f"Reconnaissance identified {previous_result.get('services_found', 'multiple')} services. "
                "Detailed enumeration will reveal versions, configurations, and potential entry points."
            ),
            PhaseType.VULNERABILITY_ASSESSMENT: (
                f"Enumeration completed with {previous_result.get('entry_points_found', 'several')} entry points. "
                "Vulnerability assessment will identify known CVEs and security weaknesses."
            ),
            PhaseType.EXPLOITATION: (
                f"Identified {previous_result.get('vuln_candidates_found', 'multiple')} vulnerability candidates. "
                "Exploitation will verify which vulnerabilities are actually exploitable."
            ),
            PhaseType.POST_EXPLOITATION: (
                "Initial access achieved. Post-exploitation will document the extent of access "
                "and gather evidence for the final report."
            ),
            PhaseType.REPORTING: (
                "All testing phases complete. Compiling findings into a comprehensive report "
                "with CVSS scores and remediation recommendations."
            ),
        }

        return rationales.get(phase, f"Proceeding with {phase.value} based on previous phase results.")

    def _generate_planned_actions_for_phase(
        self,
        phase: PhaseType,
        test_plan: TestPlan,
    ) -> List[PlannedAction]:
        """Generate planned actions in natural language (NO commands)."""
        actions_map = {
            PhaseType.RECONNAISSANCE: [
                PlannedAction(
                    summary="Scan network to discover open ports and running services",
                    objective="Build initial map of accessible services",
                    target_description="Target network/host",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Identify technologies and software versions",
                    objective="Determine technology stack for vulnerability research",
                    target_description="Discovered web services",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Gather publicly available information about the target",
                    objective="Supplement active reconnaissance with passive data",
                    target_description="Target domain and organization",
                    risk_level=RiskLevel.LOW,
                ),
            ],
            PhaseType.ENUMERATION: [
                PlannedAction(
                    summary="Gather detailed service configuration information",
                    objective="Enumerate service versions and configurations",
                    target_description="Services discovered during reconnaissance",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Map web application structure and entry points",
                    objective="Identify forms, APIs, and input validation boundaries",
                    target_description="Web applications on target",
                    risk_level=RiskLevel.MEDIUM,
                ),
                PlannedAction(
                    summary="Identify authentication mechanisms and user flows",
                    objective="Document access control implementation",
                    target_description="Application authentication endpoints",
                    risk_level=RiskLevel.MEDIUM,
                ),
            ],
            PhaseType.VULNERABILITY_ASSESSMENT: [
                PlannedAction(
                    summary="Search vulnerability databases for known issues",
                    objective="Identify CVEs affecting discovered software versions",
                    target_description="Identified technologies and versions",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Evaluate vulnerability applicability to target",
                    objective="Filter false positives and assess actual risk",
                    target_description="CVE candidates",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Research available exploits and proof-of-concepts",
                    objective="Determine exploitation feasibility",
                    target_description="Applicable vulnerabilities",
                    risk_level=RiskLevel.MEDIUM,
                ),
            ],
            PhaseType.EXPLOITATION: [
                PlannedAction(
                    summary="Verify vulnerability exploitability in controlled manner",
                    objective="Confirm vulnerabilities can be exploited",
                    target_description="Vulnerability candidates",
                    risk_level=RiskLevel.HIGH,
                    requires_approval=True,
                ),
                PlannedAction(
                    summary="Obtain proof of access with minimal impact",
                    objective="Demonstrate successful exploitation",
                    target_description="Exploitable vulnerabilities",
                    risk_level=RiskLevel.HIGH,
                    requires_approval=True,
                ),
                PlannedAction(
                    summary="Document exploitation steps for reproducibility",
                    objective="Create detailed evidence for report",
                    target_description="Successful exploits",
                    risk_level=RiskLevel.MEDIUM,
                ),
            ],
            PhaseType.REPORTING: [
                PlannedAction(
                    summary="Compile all findings with supporting evidence",
                    objective="Create comprehensive vulnerability report",
                    target_description="All collected evidence",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Assign CVSS scores to all findings",
                    objective="Provide standardized severity ratings",
                    target_description="Confirmed vulnerabilities",
                    risk_level=RiskLevel.LOW,
                ),
                PlannedAction(
                    summary="Provide remediation recommendations",
                    objective="Guide target organization in fixing issues",
                    target_description="All findings",
                    risk_level=RiskLevel.LOW,
                ),
            ],
        }

        return actions_map.get(phase, [])

    def _generate_safety_constraints_for_phase(
        self,
        phase: PhaseType,
        test_plan: TestPlan,
    ) -> List[SafetyConstraint]:
        """Generate safety constraints for a phase."""
        constraints = [
            SafetyConstraint(
                description="All operations limited to defined scope",
                constraint_type="scope",
                value="in_scope_only",
            ),
            SafetyConstraint(
                description="Full audit logging enabled",
                constraint_type="audit",
                value="all_operations",
            ),
        ]

        if phase == PhaseType.EXPLOITATION:
            constraints.extend([
                SafetyConstraint(
                    description="File read limited by Proof-of-Access policy",
                    constraint_type="data_access",
                    value="max_4096_bytes",
                ),
                SafetyConstraint(
                    description="No destructive or persistent operations",
                    constraint_type="safety",
                    value="read_only_proof",
                ),
                SafetyConstraint(
                    description="Each exploit attempt requires explicit approval",
                    constraint_type="approval",
                    value="per_exploit",
                ),
            ])

        return constraints

    def _determine_phase_risk_level(
        self,
        phase: PhaseType,
        test_plan: TestPlan,
    ) -> RiskLevel:
        """Determine overall risk level for a phase."""
        base_risk = {
            PhaseType.PLANNING: RiskLevel.LOW,
            PhaseType.RECONNAISSANCE: RiskLevel.LOW,
            PhaseType.ENUMERATION: RiskLevel.MEDIUM,
            PhaseType.VULNERABILITY_ASSESSMENT: RiskLevel.MEDIUM,
            PhaseType.EXPLOITATION: RiskLevel.HIGH,
            PhaseType.POST_EXPLOITATION: RiskLevel.HIGH,
            PhaseType.REPORTING: RiskLevel.LOW,
        }.get(phase, RiskLevel.MEDIUM)

        # Adjust based on test plan risk level
        if test_plan.overall_risk_level == RiskLevel.CRITICAL:
            if base_risk == RiskLevel.HIGH:
                return RiskLevel.CRITICAL

        return base_risk

    def _generate_phase_risk_notes(
        self,
        phase: PhaseType,
        test_plan: TestPlan,
    ) -> List[str]:
        """Generate risk notes for a phase."""
        notes_map = {
            PhaseType.RECONNAISSANCE: [
                "Network scanning may be logged by security systems",
                "Rate limiting applied to avoid triggering alerts",
            ],
            PhaseType.ENUMERATION: [
                "Active probing may trigger IDS/IPS",
                "Web crawling limited to in-scope applications",
            ],
            PhaseType.VULNERABILITY_ASSESSMENT: [
                "Vulnerability checks are non-invasive at this phase",
                "No exploitation attempts during assessment",
            ],
            PhaseType.EXPLOITATION: [
                "Each exploitation attempt requires explicit human approval",
                "Proof-of-Access policy limits data extraction",
                "All payloads are for verification only - no persistence",
                "Rollback procedures documented for each attempt",
            ],
        }

        notes = notes_map.get(phase, [])

        # Add plan-specific risks
        for risk in test_plan.risks:
            if risk.phase == phase or risk.phase is None:
                notes.append(f"Risk: {risk.description} ({risk.likelihood} likelihood)")

        return notes

    def _generate_phase_expected_outcomes(
        self,
        phase: PhaseType,
    ) -> List[str]:
        """Generate expected outcomes for a phase."""
        outcomes_map = {
            PhaseType.RECONNAISSANCE: [
                "Complete list of open ports and services",
                "Technology stack identification",
                "Initial attack surface map",
                "OSINT findings (if applicable)",
            ],
            PhaseType.ENUMERATION: [
                "Detailed service configurations",
                "Web application structure and endpoints",
                "Authentication mechanism details",
                "Potential entry points catalog",
            ],
            PhaseType.VULNERABILITY_ASSESSMENT: [
                "List of applicable CVE candidates",
                "CVSS-scored vulnerability assessments",
                "Exploitation feasibility ratings",
                "Prioritized target list for exploitation",
            ],
            PhaseType.EXPLOITATION: [
                "Proof of vulnerability exploitation",
                "Access level documentation",
                "Reproducible exploitation steps",
                "Evidence for final report",
            ],
            PhaseType.REPORTING: [
                "Executive summary of findings",
                "Detailed vulnerability descriptions",
                "CVSS scores for all findings",
                "Prioritized remediation recommendations",
            ],
        }

        return outcomes_map.get(phase, [])

    def generate_human_summary(
        self,
        test_plan: TestPlan,
        phase: Optional[PhaseType] = None,
    ) -> str:
        """
        Generate human-readable summary of current state.

        For FR-2: Natural language only, NO technical commands.

        Args:
            test_plan: Current test plan.
            phase: Optional specific phase to summarize.

        Returns:
            Human-readable summary string.
        """
        lines = []

        # Overall status
        lines.append(f"## Test Progress Summary")
        lines.append(f"")
        lines.append(f"**Status:** {test_plan.overall_status}")
        lines.append(f"**Risk Level:** {test_plan.overall_risk_level.value.upper()}")
        lines.append(f"")

        # Phase progress
        completed = sum(1 for p in test_plan.phase_sequence if p.status == PhaseStatus.COMPLETED)
        total = len(test_plan.phase_sequence)
        lines.append(f"### Phase Progress: {completed}/{total} completed")
        lines.append(f"")

        for phase_obj in test_plan.phase_sequence:
            status_icon = {
                PhaseStatus.NOT_STARTED: "⬜",
                PhaseStatus.IN_PROGRESS: "🔄",
                PhaseStatus.COMPLETED: "✅",
                PhaseStatus.SKIPPED: "⏭️",
                PhaseStatus.BLOCKED: "🚫",
                PhaseStatus.FAILED: "❌",
            }.get(phase_obj.status, "⬜")

            lines.append(f"{status_icon} {phase_obj.phase.value.replace('_', ' ').title()}")
            if phase_obj.notes:
                lines.append(f"   _{phase_obj.notes}_")

        # Open questions
        unresolved = [q for q in test_plan.open_questions if not q.resolved]
        if unresolved:
            lines.append(f"")
            lines.append(f"### Open Questions ({len(unresolved)})")
            for q in unresolved[:3]:
                lines.append(f"- [{q.priority}] {q.question}")

        # Recent changes
        if test_plan.change_log:
            lines.append(f"")
            lines.append(f"### Recent Updates")
            for change in test_plan.change_log[-3:]:
                lines.append(f"- {change.summary}")

        return "\n".join(lines)

    def get_test_plan(self) -> Optional[TestPlan]:
        """Get the current test plan."""
        return getattr(self, '_test_plan', None)

    def set_test_plan(self, test_plan: TestPlan) -> None:
        """Set the current test plan."""
        self._test_plan = test_plan
