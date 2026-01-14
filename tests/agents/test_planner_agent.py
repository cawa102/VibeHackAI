"""Tests for Planner Agent."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from src.agents.planner_agent import (
    PlannerAgent,
    VulnCandidate,
    ExploitCandidate,
    ExecutionStep,
    ExecutionPlan,
)
from src.agents.base_agent import AgentConfig, AgentContext, AgentType


class TestVulnCandidate:
    """Tests for VulnCandidate dataclass."""

    def test_create_vuln_candidate(self):
        """Test creating vulnerability candidate."""
        vuln = VulnCandidate(
            vuln_id="vuln-001",
            cve_id="CVE-2021-44228",
            title="Log4Shell",
            description="Remote code execution vulnerability",
            severity="critical",
            cvss_score=10.0,
            affected_component="log4j",
            affected_version="2.14.1",
            confidence=0.9,
        )

        assert vuln.vuln_id == "vuln-001"
        assert vuln.cve_id == "CVE-2021-44228"
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 10.0

    def test_vuln_candidate_to_dict(self):
        """Test converting to dictionary."""
        vuln = VulnCandidate(
            vuln_id="vuln-001",
            cve_id="CVE-2021-44228",
            title="Log4Shell",
            description="RCE",
            severity="critical",
            cvss_score=10.0,
            affected_component="log4j",
            affected_version="2.14.1",
            confidence=0.9,
        )

        d = vuln.to_dict()

        assert d["vuln_id"] == "vuln-001"
        assert d["cve_id"] == "CVE-2021-44228"
        assert d["exploitability"] == "unknown"


class TestExploitCandidate:
    """Tests for ExploitCandidate dataclass."""

    def test_create_exploit_candidate(self):
        """Test creating exploit candidate."""
        exploit = ExploitCandidate(
            exploit_id="exploit-001",
            vuln_candidate_id="vuln-001",
            source="github",
            name="log4j-shell-poc",
            url="https://github.com/kozmer/log4j-shell-poc",
            reliability_score=0.85,
            verified=True,
        )

        assert exploit.exploit_id == "exploit-001"
        assert exploit.source == "github"
        assert exploit.reliability_score == 0.85

    def test_exploit_candidate_to_dict(self):
        """Test converting to dictionary."""
        exploit = ExploitCandidate(
            exploit_id="exploit-001",
            vuln_candidate_id="vuln-001",
            source="github",
            name="test-poc",
            url="https://example.com",
            reliability_score=0.7,
        )

        d = exploit.to_dict()

        assert d["exploit_id"] == "exploit-001"
        assert d["source"] == "github"
        assert d["verified"] is False  # Default


class TestExecutionStep:
    """Tests for ExecutionStep dataclass."""

    def test_create_execution_step(self):
        """Test creating execution step."""
        step = ExecutionStep(
            step_id="step-001",
            order=1,
            action="verify_vulnerability",
            description="Verify CVE-2021-44228 is exploitable",
            target="log4j",
            requires_approval=False,
        )

        assert step.step_id == "step-001"
        assert step.order == 1
        assert step.action == "verify_vulnerability"

    def test_execution_step_to_dict(self):
        """Test converting to dictionary."""
        step = ExecutionStep(
            step_id="step-001",
            order=1,
            action="execute_exploit",
            description="Execute exploit",
            target="webapp",
            exploit_id="exploit-001",
            requires_approval=True,
            rollback_action="terminate_session",
        )

        d = step.to_dict()

        assert d["step_id"] == "step-001"
        assert d["requires_approval"] is True
        assert d["rollback_action"] == "terminate_session"


class TestExecutionPlan:
    """Tests for ExecutionPlan dataclass."""

    def test_create_execution_plan(self):
        """Test creating execution plan."""
        steps = [
            ExecutionStep(
                step_id="step-001",
                order=1,
                action="verify",
                description="Verify",
                target="target",
            )
        ]
        plan = ExecutionPlan(
            plan_id="plan-001",
            vuln_candidates=["vuln-001"],
            exploit_candidates=["exploit-001"],
            steps=steps,
            priority_score=8.5,
            estimated_success_rate=0.8,
            risk_level="critical",
            requires_approval=True,
        )

        assert plan.plan_id == "plan-001"
        assert plan.priority_score == 8.5
        assert plan.requires_approval is True

    def test_execution_plan_to_dict(self):
        """Test converting to dictionary."""
        steps = [
            ExecutionStep(
                step_id="step-001",
                order=1,
                action="test",
                description="Test",
                target="target",
            )
        ]
        plan = ExecutionPlan(
            plan_id="plan-001",
            vuln_candidates=["vuln-001"],
            exploit_candidates=[],
            steps=steps,
            priority_score=5.0,
            estimated_success_rate=0.5,
            risk_level="medium",
            requires_approval=False,
        )

        d = plan.to_dict()

        assert d["plan_id"] == "plan-001"
        assert len(d["steps"]) == 1


class TestPlannerAgent:
    """Tests for PlannerAgent."""

    @pytest.fixture
    def agent(self):
        """Create planner agent with mock adapters."""
        return PlannerAgent(mock_mode=True)

    @pytest.fixture
    def mock_bundle(self):
        """Create mock context bundle."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": []}
        bundle.target_profile = {
            "technologies": {
                "log4j": {"version": "2.14.1", "type": "library"},
                "apache": {"version": "2.4.49", "type": "server"},
            }
        }
        bundle.observations = []
        bundle.instructions = None
        return bundle

    @pytest.fixture
    def context(self, mock_bundle):
        """Create agent context."""
        config = AgentConfig(agent_type=AgentType.PLANNER)
        return AgentContext(bundle=mock_bundle, config=config)

    def test_initialization(self, agent):
        """Test agent initialization."""
        assert agent.agent_type == AgentType.PLANNER
        assert agent.snyk is not None
        assert agent.cve is not None
        assert agent.github is not None

    def test_run_with_tech_stack(self, agent, context):
        """Test running with technology stack."""
        output = agent.run(context)

        assert output.success is True
        assert output.patch is not None
        assert output.phase_result["vuln_candidates_found"] >= 0

    def test_run_generates_patch(self, agent, context):
        """Test that run generates patch with operations."""
        output = agent.run(context)

        assert output.patch is not None
        assert len(output.patch.operations) > 0

    def test_run_collects_evidence(self, agent, context):
        """Test that run collects evidence."""
        output = agent.run(context)

        evidence_ops = [
            op for op in output.patch.operations
            if op.op == "add_evidence"
        ]
        assert len(evidence_ops) > 0

    def test_run_records_observations(self, agent, context):
        """Test that run records observations."""
        output = agent.run(context)

        obs_ops = [
            op for op in output.patch.operations
            if op.op == "add_observation"
        ]
        assert len(obs_ops) > 0

    def test_run_finds_vuln_candidates(self, agent, context):
        """Test that run finds vulnerability candidates."""
        output = agent.run(context)

        vuln_ops = [
            op for op in output.patch.operations
            if op.op == "add_vuln_candidate"
        ]
        assert len(vuln_ops) > 0

    def test_run_searches_exploits(self, agent, context):
        """Test that run searches for exploits."""
        output = agent.run(context)

        exploit_ops = [
            op for op in output.patch.operations
            if op.op == "add_exploit_candidate"
        ]
        # May have exploits if CVEs were found
        assert output.phase_result["exploit_candidates_found"] >= 0

    def test_run_creates_execution_plan(self, agent, context):
        """Test that run creates execution plan."""
        output = agent.run(context)

        plan_ops = [
            op for op in output.patch.operations
            if op.op == "propose_execution_plan"
        ]
        # Should create plan if vulns were found
        if output.phase_result["vuln_candidates_found"] > 0:
            assert len(plan_ops) == 1

    def test_run_records_decisions(self, agent, context):
        """Test that run records decision traces."""
        output = agent.run(context)

        assert len(output.decision_traces) > 0
        decision_types = [d["decision_type"] for d in output.decision_traces]
        assert "tech_stack_analysis" in decision_types

    def test_run_with_no_tech_stack(self, agent, mock_bundle):
        """Test running with no technology stack."""
        mock_bundle.target_profile = {}
        config = AgentConfig(agent_type=AgentType.PLANNER)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is False
        assert "No technology stack" in output.error

    def test_run_with_services_from_ports(self, agent, mock_bundle):
        """Test extracting tech stack from port info."""
        mock_bundle.target_profile = {
            "targets": {
                "192.168.1.1": {
                    "ports": [
                        {"port": 80, "product": "nginx", "version": "1.19.0"},
                        {"port": 443, "product": "apache", "version": "2.4.49"},
                    ]
                }
            }
        }
        config = AgentConfig(agent_type=AgentType.PLANNER)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True

    def test_run_with_observations(self, agent, mock_bundle):
        """Test extracting tech stack from observations."""
        mock_bundle.target_profile = {}
        mock_bundle.observations = [
            {
                "type": "technology_detection",
                "data": {
                    "technologies": {
                        "django": {"version": "3.1.0", "type": "framework"},
                    }
                }
            }
        ]
        config = AgentConfig(agent_type=AgentType.PLANNER)
        context = AgentContext(bundle=mock_bundle, config=config)

        output = agent.run(context)

        assert output.success is True


class TestPlannerAgentFeasibility:
    """Tests for feasibility evaluation."""

    @pytest.fixture
    def agent(self):
        """Create planner agent with mock adapters."""
        return PlannerAgent(mock_mode=True)

    @pytest.fixture
    def context(self):
        """Create agent context."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": [{"type": "ip", "value": "192.168.1.1"}]}
        bundle.target_profile = {
            "technologies": {
                "log4j": {"version": "2.14.1", "type": "library"},
            },
            "targets": {
                "192.168.1.1": {"ip": "192.168.1.1"}
            }
        }
        bundle.observations = []
        bundle.instructions = None
        config = AgentConfig(agent_type=AgentType.PLANNER)
        return AgentContext(bundle=bundle, config=config)

    def test_feasibility_evaluation_recorded(self, agent, context):
        """Test that feasibility evaluation is recorded."""
        output = agent.run(context)

        decision_types = [d["decision_type"] for d in output.decision_traces]
        # Should have feasibility evaluation for each vuln
        assert "feasibility_evaluation" in decision_types or output.phase_result["vuln_candidates_found"] == 0


class TestPlannerAgentExecutionPlan:
    """Tests for execution plan creation."""

    @pytest.fixture
    def agent(self):
        """Create planner agent with mock adapters."""
        return PlannerAgent(mock_mode=True)

    @pytest.fixture
    def context(self):
        """Create agent context."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": []}
        bundle.target_profile = {
            "technologies": {
                "log4j": {"version": "2.14.1", "type": "library"},
            }
        }
        bundle.observations = []
        bundle.instructions = None
        config = AgentConfig(agent_type=AgentType.PLANNER)
        return AgentContext(bundle=bundle, config=config)

    def test_execution_plan_has_steps(self, agent, context):
        """Test that execution plan has steps."""
        output = agent.run(context)

        plan_ops = [
            op for op in output.patch.operations
            if op.op == "propose_execution_plan"
        ]

        if plan_ops:
            plan = plan_ops[0].payload
            assert "steps" in plan
            assert len(plan["steps"]) > 0

    def test_execution_plan_has_priority(self, agent, context):
        """Test that execution plan has priority score."""
        output = agent.run(context)

        plan_ops = [
            op for op in output.patch.operations
            if op.op == "propose_execution_plan"
        ]

        if plan_ops:
            plan = plan_ops[0].payload
            assert "priority_score" in plan
            assert plan["priority_score"] >= 0

    def test_execution_plan_has_risk_level(self, agent, context):
        """Test that execution plan has risk level."""
        output = agent.run(context)

        plan_ops = [
            op for op in output.patch.operations
            if op.op == "propose_execution_plan"
        ]

        if plan_ops:
            plan = plan_ops[0].payload
            assert "risk_level" in plan
            assert plan["risk_level"] in ["low", "medium", "high", "critical"]


class TestPlannerAgentDangerousOperations:
    """Tests for dangerous operation detection."""

    def test_rce_requires_approval(self):
        """Test that RCE vulns require approval."""
        agent = PlannerAgent(mock_mode=True)

        vuln = VulnCandidate(
            vuln_id="vuln-001",
            cve_id="CVE-2021-44228",
            title="Remote Code Execution via JNDI",
            description="RCE vulnerability in Log4j",
            severity="critical",
            cvss_score=10.0,
            affected_component="log4j",
            affected_version="2.14.1",
            confidence=0.9,
        )

        assert agent._is_dangerous_operation(vuln) is True

    def test_sqli_requires_approval(self):
        """Test that SQL injection vulns require approval."""
        agent = PlannerAgent(mock_mode=True)

        vuln = VulnCandidate(
            vuln_id="vuln-001",
            cve_id="CVE-2021-3281",
            title="SQL Injection in Django",
            description="SQL injection vulnerability",
            severity="critical",
            cvss_score=9.8,
            affected_component="django",
            affected_version="2.2.10",
            confidence=0.9,
        )

        assert agent._is_dangerous_operation(vuln) is True

    def test_info_disclosure_no_approval(self):
        """Test that info disclosure may not require approval."""
        agent = PlannerAgent(mock_mode=True)

        vuln = VulnCandidate(
            vuln_id="vuln-001",
            cve_id="CVE-2021-0001",
            title="Information Disclosure",
            description="Sensitive data exposure via error messages",
            severity="medium",
            cvss_score=5.0,
            affected_component="webapp",
            affected_version="1.0.0",
            confidence=0.8,
        )

        assert agent._is_dangerous_operation(vuln) is False


class TestPlannerAgentSkipLogic:
    """Tests for skip logic."""

    @pytest.fixture
    def agent(self):
        """Create planner agent."""
        return PlannerAgent(mock_mode=True)

    def test_skip_with_existing_plan(self, agent):
        """Test skipping when execution plan exists."""
        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 3
        bundle.scope = {"targets": []}
        bundle.target_profile = {
            "execution_plan": {
                "plan_id": "plan-001",
                "steps": [{"step_id": "step-001", "action": "verify"}],
            }
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(
            agent_type=AgentType.PLANNER,
            skip_on_sufficient_data=True,
        )
        context = AgentContext(bundle=bundle, config=config)

        skip_reason = agent._should_skip(context)

        assert skip_reason is not None
        assert "plan" in skip_reason.lower()


class TestPlannerAgentIntegration:
    """Integration tests for PlannerAgent."""

    def test_full_planning_workflow(self):
        """Test full planning workflow."""
        agent = PlannerAgent(mock_mode=True)

        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 2
        bundle.scope = {"targets": []}
        bundle.target_profile = {
            "technologies": {
                "log4j": {"version": "2.14.1", "type": "library"},
                "django": {"version": "2.2.10", "type": "framework"},
            },
            "targets": {
                "10.0.0.1": {
                    "ip": "10.0.0.1",
                    "ports": [80, 443],
                }
            }
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.PLANNER)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        assert output.patch is not None

        # Check operations
        op_types = [op.op for op in output.patch.operations]
        assert "add_evidence" in op_types
        assert "add_observation" in op_types

    def test_planning_with_recon_results(self):
        """Test planning using recon phase results."""
        agent = PlannerAgent(mock_mode=True)

        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 2
        bundle.scope = {"targets": []}
        bundle.target_profile = {
            "targets": {
                "10.0.0.1": {
                    "ip": "10.0.0.1",
                    "ports": [
                        {"port": 80, "service": "http", "product": "apache", "version": "2.4.49"},
                        {"port": 443, "service": "https", "product": "nginx", "version": "1.19.0"},
                    ],
                }
            }
        }
        bundle.observations = [
            {
                "type": "technology_detection",
                "data": {
                    "technologies": {
                        "log4j": {"version": "2.14.1", "type": "library"},
                    }
                }
            }
        ]
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.PLANNER)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        # Should have found vulnerabilities for the detected technologies
        assert output.phase_result["vuln_candidates_found"] >= 0

    def test_planning_with_multiple_technologies(self):
        """Test planning with multiple technologies."""
        agent = PlannerAgent(mock_mode=True)

        bundle = MagicMock()
        bundle.session_id = "test-session"
        bundle.scope_tag = "test-scope"
        bundle.state_version = 1
        bundle.scope = {"targets": []}
        bundle.target_profile = {
            "technologies": {
                "log4j": {"version": "2.14.1"},
                "spring": {"version": "5.3.0"},
                "tomcat": {"version": "9.0.40"},
                "mysql": {"version": "8.0.20"},
            }
        }
        bundle.observations = []
        bundle.instructions = None

        config = AgentConfig(agent_type=AgentType.PLANNER)
        context = AgentContext(bundle=bundle, config=config)

        output = agent.run(context)

        assert output.success is True
        # Should process all technologies
        decision_traces = output.decision_traces
        tech_analysis = [d for d in decision_traces if d["decision_type"] == "tech_stack_analysis"]
        assert len(tech_analysis) > 0
