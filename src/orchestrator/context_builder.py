"""
Context Builder for Orchestrator.

Generates context bundles with relevant information for each agent type.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .router import Phase

if TYPE_CHECKING:
    from ..storage.state_store import StateStore
    from ..storage.evidence_ledger import EvidenceLedger


@dataclass
class ContextBundle:
    """
    Context bundle for an agent.

    Contains all information an agent needs to perform its task.
    """
    agent_type: str
    session_id: str
    scope_tag: str
    state_version: int
    phase: str
    scope: Optional[Dict[str, Any]] = None
    target_profile: Optional[Dict[str, Any]] = None
    observations: List[Dict[str, Any]] = dataclass_field(default_factory=list)
    vuln_candidates: List[Dict[str, Any]] = dataclass_field(default_factory=list)
    exploit_candidates: List[Dict[str, Any]] = dataclass_field(default_factory=list)
    execution_plans: List[Dict[str, Any]] = dataclass_field(default_factory=list)
    execution_results: List[Dict[str, Any]] = dataclass_field(default_factory=list)
    finding_candidates: List[Dict[str, Any]] = dataclass_field(default_factory=list)
    decision_traces: List[Dict[str, Any]] = dataclass_field(default_factory=list)
    evidence_refs: List[str] = dataclass_field(default_factory=list)
    previous_phase_result: Optional[Dict[str, Any]] = None
    instructions: Optional[str] = None
    created_at: datetime = dataclass_field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "agent_type": self.agent_type,
            "session_id": self.session_id,
            "scope_tag": self.scope_tag,
            "state_version": self.state_version,
            "phase": self.phase,
            "scope": self.scope,
            "target_profile": self.target_profile,
            "observations": self.observations,
            "vuln_candidates": self.vuln_candidates,
            "exploit_candidates": self.exploit_candidates,
            "execution_plans": self.execution_plans,
            "execution_results": self.execution_results,
            "finding_candidates": self.finding_candidates,
            "decision_traces": self.decision_traces,
            "evidence_refs": self.evidence_refs,
            "previous_phase_result": self.previous_phase_result,
            "instructions": self.instructions,
            "created_at": self.created_at.isoformat() + "Z",
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContextBundle":
        """Create from dictionary."""
        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.rstrip("Z"))

        return cls(
            agent_type=data["agent_type"],
            session_id=data["session_id"],
            scope_tag=data["scope_tag"],
            state_version=data["state_version"],
            phase=data["phase"],
            scope=data.get("scope"),
            target_profile=data.get("target_profile"),
            observations=data.get("observations", []),
            vuln_candidates=data.get("vuln_candidates", []),
            exploit_candidates=data.get("exploit_candidates", []),
            execution_plans=data.get("execution_plans", []),
            execution_results=data.get("execution_results", []),
            finding_candidates=data.get("finding_candidates", []),
            decision_traces=data.get("decision_traces", []),
            evidence_refs=data.get("evidence_refs", []),
            previous_phase_result=data.get("previous_phase_result"),
            instructions=data.get("instructions"),
            created_at=created_at or datetime.utcnow(),
        )


# Agent-specific required context
AGENT_CONTEXT_REQUIREMENTS = {
    "recon_agent": {
        "include": ["scope", "target_profile"],
        "observations_limit": 10,
        "include_decisions": False,
    },
    "enumeration_agent": {
        "include": ["scope", "target_profile", "observations"],
        "observations_limit": 50,
        "include_decisions": False,
    },
    "planner_agent": {
        "include": [
            "scope", "target_profile", "observations",
            "vuln_candidates", "exploit_candidates"
        ],
        "observations_limit": 100,
        "include_decisions": True,
    },
    "exploitation_agent": {
        "include": [
            "scope", "target_profile", "observations",
            "vuln_candidates", "exploit_candidates",
            "execution_plans", "execution_results"
        ],
        "observations_limit": 50,
        "include_decisions": True,
    },
    "reporting_agent": {
        "include": [
            "scope", "target_profile", "observations",
            "vuln_candidates", "exploit_candidates",
            "execution_plans", "execution_results",
            "finding_candidates", "decision_traces"
        ],
        "observations_limit": None,  # All
        "include_decisions": True,
    },
}


class ContextBuilder:
    """
    Builds context bundles for agents.

    Extracts and minimizes relevant information for each agent type.
    """

    def __init__(
        self,
        state_store: "StateStore",
        evidence_ledger: "EvidenceLedger",
        session_id: str,
        scope_tag: str,
    ):
        """
        Initialize context builder.

        Args:
            state_store: State store for reading state.
            evidence_ledger: Evidence ledger for evidence refs.
            session_id: Current session ID.
            scope_tag: Current scope tag.
        """
        self.state_store = state_store
        self.evidence_ledger = evidence_ledger
        self.session_id = session_id
        self.scope_tag = scope_tag

    def build(
        self,
        agent_type: str,
        phase: Phase,
        previous_result: Optional[Dict[str, Any]] = None,
        instructions: Optional[str] = None,
    ) -> ContextBundle:
        """
        Build a context bundle for an agent.

        Args:
            agent_type: Type of agent (recon_agent, etc.).
            phase: Current phase.
            previous_result: Result from previous phase.
            instructions: Optional specific instructions.

        Returns:
            ContextBundle for the agent.
        """
        state_version = self.state_store.get_version()

        # Get requirements for this agent
        requirements = AGENT_CONTEXT_REQUIREMENTS.get(
            agent_type,
            AGENT_CONTEXT_REQUIREMENTS["recon_agent"]
        )

        bundle = ContextBundle(
            agent_type=agent_type,
            session_id=self.session_id,
            scope_tag=self.scope_tag,
            state_version=state_version,
            phase=phase.value,
            previous_phase_result=previous_result,
            instructions=instructions,
        )

        # Build context based on requirements
        include_list = requirements.get("include", [])

        if "scope" in include_list:
            bundle.scope = self._load_scope()

        if "target_profile" in include_list:
            bundle.target_profile = self._load_target_profile()

        if "observations" in include_list:
            limit = requirements.get("observations_limit")
            bundle.observations = self._load_observations(limit)

        if "vuln_candidates" in include_list:
            bundle.vuln_candidates = self._load_vuln_candidates()

        if "exploit_candidates" in include_list:
            bundle.exploit_candidates = self._load_exploit_candidates()

        if "execution_plans" in include_list:
            bundle.execution_plans = self._load_execution_plans()

        if "execution_results" in include_list:
            bundle.execution_results = self._load_execution_results()

        if "finding_candidates" in include_list:
            bundle.finding_candidates = self._load_finding_candidates()

        if requirements.get("include_decisions"):
            bundle.decision_traces = self._load_decision_traces()

        # Collect evidence references
        bundle.evidence_refs = self._collect_evidence_refs(bundle)

        return bundle

    def _load_scope(self) -> Optional[Dict[str, Any]]:
        """Load scope from state store."""
        try:
            return self.state_store.read_json("scope.json")
        except FileNotFoundError:
            return None

    def _load_target_profile(self) -> Optional[Dict[str, Any]]:
        """Load target profile from state store."""
        try:
            return self.state_store.read_json("target_profile.json")
        except FileNotFoundError:
            return None

    def _load_observations(
        self,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Load observations from state store."""
        try:
            observations = self.state_store.read_jsonl("observations.jsonl")
            if limit:
                return observations[-limit:]
            return observations
        except Exception:
            return []

    def _load_vuln_candidates(self) -> List[Dict[str, Any]]:
        """Load vulnerability candidates."""
        try:
            vulns = self.state_store.read_jsonl("vuln_candidates.jsonl")
            # Filter out false positives
            return [v for v in vulns if not v.get("false_positive")]
        except Exception:
            return []

    def _load_exploit_candidates(self) -> List[Dict[str, Any]]:
        """Load exploit candidates."""
        try:
            return self.state_store.read_jsonl("exploit_candidates.jsonl")
        except Exception:
            return []

    def _load_execution_plans(self) -> List[Dict[str, Any]]:
        """Load execution plans."""
        try:
            data = self.state_store.read_json("execution_plans.json")
            return data.get("plans", [])
        except FileNotFoundError:
            return []

    def _load_execution_results(self) -> List[Dict[str, Any]]:
        """Load execution results."""
        try:
            return self.state_store.read_jsonl("execution_results.jsonl")
        except Exception:
            return []

    def _load_finding_candidates(self) -> List[Dict[str, Any]]:
        """Load finding candidates."""
        try:
            return self.state_store.read_jsonl("finding_candidates.jsonl")
        except Exception:
            return []

    def _load_decision_traces(self) -> List[Dict[str, Any]]:
        """Load decision traces."""
        try:
            return self.state_store.read_jsonl("decision_traces.jsonl")
        except Exception:
            return []

    def _collect_evidence_refs(self, bundle: ContextBundle) -> List[str]:
        """Collect all evidence references from bundle."""
        evidence_ids = set()

        # Collect from various sources
        for obs in bundle.observations:
            for eid in obs.get("evidence_ids", []):
                evidence_ids.add(eid)

        for vuln in bundle.vuln_candidates:
            for eid in vuln.get("evidence_ids", []):
                evidence_ids.add(eid)

        for finding in bundle.finding_candidates:
            for eid in finding.get("evidence_ids", []):
                evidence_ids.add(eid)

        for result in bundle.execution_results:
            for eid in result.get("evidence_ids", []):
                evidence_ids.add(eid)

        return list(evidence_ids)

    def save_bundle(self, bundle: ContextBundle) -> str:
        """
        Save bundle to state store.

        Args:
            bundle: The context bundle to save.

        Returns:
            Path to saved bundle.
        """
        return self.state_store.save_context_bundle(
            agent_type=bundle.agent_type,
            bundle=bundle.to_dict(),
        )

    def get_minimal_bundle(
        self,
        agent_type: str,
        phase: Phase,
    ) -> ContextBundle:
        """
        Build a minimal context bundle (for efficiency).

        Only includes essential information.

        Args:
            agent_type: Type of agent.
            phase: Current phase.

        Returns:
            Minimal ContextBundle.
        """
        state_version = self.state_store.get_version()

        return ContextBundle(
            agent_type=agent_type,
            session_id=self.session_id,
            scope_tag=self.scope_tag,
            state_version=state_version,
            phase=phase.value,
            scope=self._load_scope(),
        )
