"""
Unit tests for PentestAgent schemas.
"""

import pytest
from datetime import datetime, timedelta

from src.schemas.base import BaseSchema, SCHEMA_VERSION
from src.schemas.scope import Scope, TargetSpec, TargetType, AllowedOperation
from src.schemas.target_profile import (
    TargetProfile, HostInfo, PortInfo, PortState, Protocol, TechnologyStack, ServiceInfo
)
from src.schemas.evidence import EvidenceItem
from src.schemas.observation import Observation, ObservationStatus
from src.schemas.vuln_candidate import VulnCandidate, Severity, ConfidenceLevel
from src.schemas.exploit_candidate import ExploitCandidate, ExploitSource
from src.schemas.execution_plan import ExecutionPlan, ExecutionStep, StepType, RiskLevel
from src.schemas.execution_result import ExecutionResult, ExecutionStatus, ErrorClass
from src.schemas.finding_candidate import FindingCandidate, FindingSeverity
from src.schemas.decision_trace import DecisionTrace, DecisionType, DecisionOption
from src.schemas.validators import (
    validate_evidence_ids,
    validate_scope_tag,
    validate_finding_evidence_requirement,
    EvidenceValidationError,
    ScopeValidationError,
)


class TestBaseSchema:
    """Tests for BaseSchema."""

    def test_auto_generate_id(self):
        """Test that ID is auto-generated."""
        # Create a concrete subclass for testing
        class TestSchema(BaseSchema):
            pass

        obj = TestSchema(
            session_id="test-session",
            created_by="test",
            scope_tag="192.168.1.1",
        )

        assert obj.id is not None
        assert len(obj.id) == 36  # UUID format

    def test_default_schema_version(self):
        """Test that schema version defaults to current."""
        class TestSchema(BaseSchema):
            pass

        obj = TestSchema(
            session_id="test-session",
            created_by="test",
            scope_tag="192.168.1.1",
        )

        assert obj.schema_version == SCHEMA_VERSION

    def test_created_at_defaults_to_now(self):
        """Test that created_at defaults to current time."""
        class TestSchema(BaseSchema):
            pass

        before = datetime.utcnow()
        obj = TestSchema(
            session_id="test-session",
            created_by="test",
            scope_tag="192.168.1.1",
        )
        after = datetime.utcnow()

        assert before <= obj.created_at <= after

    def test_created_by_validation(self):
        """Test that empty created_by raises error."""
        class TestSchema(BaseSchema):
            pass

        with pytest.raises(ValueError, match="created_by cannot be empty"):
            TestSchema(
                session_id="test-session",
                created_by="",
                scope_tag="192.168.1.1",
            )

    def test_scope_tag_validation(self):
        """Test that empty scope_tag raises error."""
        class TestSchema(BaseSchema):
            pass

        with pytest.raises(ValueError, match="scope_tag cannot be empty"):
            TestSchema(
                session_id="test-session",
                created_by="test",
                scope_tag="",
            )


class TestScope:
    """Tests for Scope schema."""

    def test_create_scope(self):
        """Test creating a basic scope."""
        scope = Scope(
            session_id="test-session",
            created_by="human",
            scope_tag="engagement-001",
        )

        assert scope.targets == []
        assert scope.allowed_operations == []

    def test_add_target(self):
        """Test adding targets to scope."""
        scope = Scope(
            session_id="test-session",
            created_by="human",
            scope_tag="engagement-001",
        )

        scope.add_target("192.168.1.1", TargetType.IP)
        scope.add_target("example.com", TargetType.DOMAIN)

        assert len(scope.targets) == 2

    def test_is_target_allowed(self):
        """Test target allowance checking."""
        scope = Scope(
            session_id="test-session",
            created_by="human",
            scope_tag="engagement-001",
            targets=[
                TargetSpec(value="192.168.1.1", type=TargetType.IP),
            ],
        )

        assert scope.is_target_allowed("192.168.1.1", TargetType.IP) is True
        assert scope.is_target_allowed("192.168.1.2", TargetType.IP) is False

    def test_is_operation_allowed(self):
        """Test operation allowance checking."""
        scope = Scope(
            session_id="test-session",
            created_by="human",
            scope_tag="engagement-001",
            allowed_operations=[AllowedOperation.PORT_SCAN],
        )

        assert scope.is_operation_allowed(AllowedOperation.PORT_SCAN) is True
        assert scope.is_operation_allowed(AllowedOperation.EXPLOIT_EXECUTE) is False

    def test_scope_expiration(self):
        """Test scope expiration checking."""
        # Non-expired
        scope = Scope(
            session_id="test-session",
            created_by="human",
            scope_tag="engagement-001",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )
        assert scope.is_expired() is False

        # Expired
        scope_expired = Scope(
            session_id="test-session",
            created_by="human",
            scope_tag="engagement-001",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )
        assert scope_expired.is_expired() is True


class TestTargetProfile:
    """Tests for TargetProfile schema."""

    def test_create_target_profile(self):
        """Test creating a target profile."""
        profile = TargetProfile(
            session_id="test-session",
            created_by="recon_agent",
            scope_tag="192.168.1.1",
        )

        assert profile.hosts == []
        assert profile.technologies == []

    def test_add_host(self):
        """Test adding hosts."""
        profile = TargetProfile(
            session_id="test-session",
            created_by="recon_agent",
            scope_tag="192.168.1.1",
        )

        host = HostInfo(ip="192.168.1.1", hostname="server1")
        profile.add_host(host)

        assert len(profile.hosts) == 1
        assert profile.get_host("192.168.1.1") is not None

    def test_add_port_to_host(self):
        """Test adding ports to a host."""
        host = HostInfo(ip="192.168.1.1")
        service_info = ServiceInfo(name="http", version="1.1")
        port = PortInfo(port=80, protocol="tcp", state="open", service=service_info)
        host.add_port(port)

        assert len(host.ports) == 1
        assert host.get_port(80) is not None
        assert host.get_port(80).service.name == "http"


class TestEvidenceItem:
    """Tests for EvidenceItem schema."""

    def test_create_evidence_item(self):
        """Test creating an evidence item."""
        item = EvidenceItem(
            evidence_id="ev-12345678-1234-1234-1234-123456789012",
            file_path="/evidence/ev-123/raw.xml",
            sha256="a" * 64,
            size_bytes=1024,
            source_tool="nmap",
        )

        assert item.evidence_id.startswith("ev-")
        assert len(item.sha256) == 64

    def test_invalid_evidence_id(self):
        """Test that invalid evidence_id raises error."""
        with pytest.raises(ValueError, match="must start with 'ev-'"):
            EvidenceItem(
                evidence_id="invalid-id",
                file_path="/evidence/test/raw.bin",
                sha256="a" * 64,
                size_bytes=100,
                source_tool="test",
            )

    def test_invalid_sha256(self):
        """Test that invalid sha256 raises error."""
        with pytest.raises(ValueError, match="must be a 64-character"):
            EvidenceItem(
                evidence_id="ev-12345678-1234-1234-1234-123456789012",
                file_path="/evidence/test/raw.bin",
                sha256="invalid",
                size_bytes=100,
                source_tool="test",
            )


class TestObservation:
    """Tests for Observation schema."""

    def test_create_observation(self):
        """Test creating an observation."""
        obs = Observation(
            session_id="test-session",
            created_by="recon_agent",
            scope_tag="192.168.1.1",
            tool="nmap",
            action="port_scan",
            target="192.168.1.1",
        )

        assert obs.tool == "nmap"
        assert obs.status == ObservationStatus.SUCCESS

    def test_mark_completed(self):
        """Test marking observation as completed."""
        obs = Observation(
            session_id="test-session",
            created_by="recon_agent",
            scope_tag="192.168.1.1",
            tool="nmap",
            action="port_scan",
            target="192.168.1.1",
        )

        obs.mark_completed(status=ObservationStatus.SUCCESS)

        assert obs.completed_at is not None
        assert obs.duration_ms is not None


class TestVulnCandidate:
    """Tests for VulnCandidate schema."""

    def test_create_vuln_candidate(self):
        """Test creating a vulnerability candidate."""
        vuln = VulnCandidate(
            session_id="test-session",
            created_by="planner_agent",
            scope_tag="192.168.1.1",
            title="SQL Injection",
            description="SQL injection vulnerability in login form",
            affected_component="https://example.com/login",
            source="manual",
        )

        assert vuln.title == "SQL Injection"
        assert vuln.severity == Severity.UNKNOWN

    def test_cve_id_validation(self):
        """Test CVE ID validation."""
        vuln = VulnCandidate(
            session_id="test-session",
            created_by="planner_agent",
            scope_tag="192.168.1.1",
            title="Log4Shell",
            description="Remote code execution via Log4j",
            affected_component="app-server:8080",
            source="cve-research",
            cve_id="cve-2021-44228",  # lowercase should be normalized
        )

        assert vuln.cve_id == "CVE-2021-44228"

    def test_is_high_severity(self):
        """Test high severity check."""
        vuln = VulnCandidate(
            session_id="test-session",
            created_by="planner_agent",
            scope_tag="192.168.1.1",
            title="Critical Vuln",
            description="Test",
            affected_component="test",
            source="test",
            severity=Severity.CRITICAL,
        )

        assert vuln.is_high_severity() is True


class TestExploitCandidate:
    """Tests for ExploitCandidate schema."""

    def test_create_exploit_candidate(self):
        """Test creating an exploit candidate."""
        exploit = ExploitCandidate(
            session_id="test-session",
            created_by="planner_agent",
            scope_tag="192.168.1.1",
            vuln_candidate_id="vuln-123",
            title="Metasploit module for Log4Shell",
            source=ExploitSource.METASPLOIT,
            module_name="exploit/multi/http/log4shell_header_injection",
        )

        assert exploit.source == ExploitSource.METASPLOIT
        assert exploit.is_framework_exploit() is True


class TestExecutionPlan:
    """Tests for ExecutionPlan schema."""

    def test_create_execution_plan(self):
        """Test creating an execution plan."""
        plan = ExecutionPlan(
            session_id="test-session",
            created_by="planner_agent",
            scope_tag="192.168.1.1",
            title="Exploit Log4Shell",
            description="Verify Log4Shell vulnerability",
            target="192.168.1.1:8080",
        )

        assert plan.approved is False
        assert plan.requires_approval is True

    def test_add_step(self):
        """Test adding steps to a plan."""
        plan = ExecutionPlan(
            session_id="test-session",
            created_by="planner_agent",
            scope_tag="192.168.1.1",
            title="Test Plan",
            description="Test",
            target="192.168.1.1",
        )

        step = ExecutionStep(
            step_index=0,
            title="Verify connectivity",
            description="Check if target is reachable",
            tool="ping",
            action="ping",
            requires_approval=False,
        )
        plan.add_step(step)

        assert len(plan.steps) == 1

    def test_approve_plan(self):
        """Test approving a plan."""
        plan = ExecutionPlan(
            session_id="test-session",
            created_by="planner_agent",
            scope_tag="192.168.1.1",
            title="Test Plan",
            description="Test",
            target="192.168.1.1",
        )

        plan.approve("human_tester")

        assert plan.approved is True
        assert plan.approved_by == "human_tester"
        assert plan.approved_at is not None


class TestExecutionResult:
    """Tests for ExecutionResult schema."""

    def test_create_execution_result(self):
        """Test creating an execution result."""
        result = ExecutionResult(
            session_id="test-session",
            created_by="exploitation_agent",
            scope_tag="192.168.1.1",
            plan_id="plan-123",
            step_index=0,
        )

        assert result.status == ExecutionStatus.PENDING

    def test_mark_success(self):
        """Test marking result as success."""
        result = ExecutionResult(
            session_id="test-session",
            created_by="exploitation_agent",
            scope_tag="192.168.1.1",
            plan_id="plan-123",
            step_index=0,
        )

        result.mark_success(output_summary="Target vulnerable")

        assert result.status == ExecutionStatus.SUCCESS
        assert result.completed_at is not None

    def test_mark_failure(self):
        """Test marking result as failure."""
        result = ExecutionResult(
            session_id="test-session",
            created_by="exploitation_agent",
            scope_tag="192.168.1.1",
            plan_id="plan-123",
            step_index=0,
        )

        result.mark_failure(
            error_class=ErrorClass.NETWORK,
            error_message="Connection refused",
        )

        assert result.status == ExecutionStatus.FAILURE
        assert result.error_class == ErrorClass.NETWORK


class TestFindingCandidate:
    """Tests for FindingCandidate schema."""

    def test_create_finding_candidate(self):
        """Test creating a finding candidate."""
        finding = FindingCandidate(
            session_id="test-session",
            created_by="exploitation_agent",
            scope_tag="192.168.1.1",
            title="SQL Injection in Login",
            severity=FindingSeverity.MEDIUM,
            description="The login form is vulnerable to SQL injection",
            impact="Attackers can bypass authentication",
            affected_component="https://example.com/login",
            remediation="Use parameterized queries",
            evidence_ids=["ev-123"],
        )

        assert finding.promoted is False

    def test_high_severity_requires_two_evidence(self):
        """Test that high severity findings require 2 evidence items."""
        with pytest.raises(ValueError, match="require at least 2 evidence"):
            FindingCandidate(
                session_id="test-session",
                created_by="exploitation_agent",
                scope_tag="192.168.1.1",
                title="Critical Finding",
                severity=FindingSeverity.CRITICAL,
                description="Critical vulnerability",
                impact="Full system compromise",
                affected_component="server",
                remediation="Patch immediately",
                evidence_ids=["ev-123"],  # Only 1 evidence
            )

    def test_high_severity_with_sufficient_evidence(self):
        """Test creating high severity finding with sufficient evidence."""
        finding = FindingCandidate(
            session_id="test-session",
            created_by="exploitation_agent",
            scope_tag="192.168.1.1",
            title="Critical Finding",
            severity=FindingSeverity.CRITICAL,
            description="Critical vulnerability",
            impact="Full system compromise",
            affected_component="server",
            remediation="Patch immediately",
            evidence_ids=["ev-123", "ev-456"],  # 2 evidence items
        )

        assert finding.can_be_promoted() is True

    def test_promote_finding(self):
        """Test promoting a finding."""
        finding = FindingCandidate(
            session_id="test-session",
            created_by="exploitation_agent",
            scope_tag="192.168.1.1",
            title="Medium Finding",
            severity=FindingSeverity.MEDIUM,
            description="Vulnerability",
            impact="Limited impact",
            affected_component="server",
            remediation="Fix it",
            evidence_ids=["ev-123"],
        )

        finding.promote("human_reviewer")

        assert finding.promoted is True
        assert finding.promoted_by == "human_reviewer"


class TestDecisionTrace:
    """Tests for DecisionTrace schema."""

    def test_create_decision_trace(self):
        """Test creating a decision trace."""
        trace = DecisionTrace(
            session_id="test-session",
            created_by="orchestrator",
            scope_tag="192.168.1.1",
            decision_type=DecisionType.PHASE_TRANSITION,
            context="Deciding whether to move from recon to enumeration",
            rationale="Sufficient target information gathered",
        )

        assert trace.automated is True
        assert trace.human_override is False

    def test_add_option(self):
        """Test adding options to a decision."""
        trace = DecisionTrace(
            session_id="test-session",
            created_by="orchestrator",
            scope_tag="192.168.1.1",
            decision_type=DecisionType.TOOL_SELECTION,
            context="Selecting scanning tool",
            rationale="Nmap provides comprehensive port scanning",
        )

        trace.add_option(DecisionOption(
            option_id="nmap",
            description="Use Nmap for port scanning",
            pros=["Comprehensive", "Well-known"],
            cons=["Can be slow"],
        ))

        assert len(trace.options) == 1

    def test_phase_transition_factory(self):
        """Test phase transition factory method."""
        trace = DecisionTrace.create_phase_transition(
            session_id="test-session",
            from_phase="recon",
            to_phase="enumeration",
            rationale="Recon complete",
            created_by="orchestrator",
            scope_tag="192.168.1.1",
        )

        assert trace.decision_type == DecisionType.PHASE_TRANSITION
        assert len(trace.options) == 2


class TestValidators:
    """Tests for validator functions."""

    def test_validate_evidence_ids_success(self):
        """Test evidence ID validation passes."""
        existing = {"ev-123", "ev-456", "ev-789"}
        # Should not raise
        validate_evidence_ids(["ev-123", "ev-456"], existing, min_required=1)

    def test_validate_evidence_ids_missing(self):
        """Test evidence ID validation fails for missing IDs."""
        existing = {"ev-123"}
        with pytest.raises(EvidenceValidationError, match="not found"):
            validate_evidence_ids(["ev-123", "ev-999"], existing)

    def test_validate_evidence_ids_insufficient(self):
        """Test evidence ID validation fails for insufficient count."""
        existing = {"ev-123"}
        with pytest.raises(EvidenceValidationError, match="requires at least 2"):
            validate_evidence_ids(["ev-123"], existing, min_required=2)

    def test_validate_finding_evidence_high_severity(self):
        """Test finding evidence validation for high severity."""
        with pytest.raises(EvidenceValidationError, match="require at least 2"):
            validate_finding_evidence_requirement(
                FindingSeverity.HIGH,
                ["ev-123"],  # Only 1
            )

    def test_validate_scope_tag_expired(self):
        """Test scope tag validation fails for expired scope."""
        scope = Scope(
            session_id="test-session",
            created_by="human",
            scope_tag="test",
            expires_at=datetime.utcnow() - timedelta(hours=1),
        )

        with pytest.raises(ScopeValidationError, match="expired"):
            validate_scope_tag("192.168.1.1", scope)
