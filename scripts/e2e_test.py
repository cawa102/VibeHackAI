#!/usr/bin/env python3
"""
E2E Test Script for PentestAgent.

Target: 192.168.64.23 (CryptoBank VM)
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.orchestrator.orchestrator import Orchestrator, OrchestratorConfig, AgentResult
from src.orchestrator.router import Phase
from src.orchestrator.approval_gate import ApprovalRequest, ApprovalResult
from src.storage.state_store import StateStore
from src.storage.evidence_ledger import EvidenceLedger
from src.storage.session_manager import SessionManager


# Target configuration
TARGET_IP = "192.168.64.23"
SESSION_ID = f"e2e-test-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
WORKSPACE_DIR = project_root / "workspace"


def create_initial_scope():
    """Create initial scope for the target."""
    return {
        "id": f"scope-{SESSION_ID}",
        "session_id": SESSION_ID,
        "targets": [
            {"type": "ip", "value": TARGET_IP},
        ],
        "allowed_operations": [
            "scan",
            "enumerate",
            "exploit",
        ],
        "excluded_targets": [],
        "restrictions": [
            "No DoS attacks",
            "No data exfiltration",
            "No persistence mechanisms",
        ],
        "created_at": datetime.utcnow().isoformat() + "Z",
        "created_by": "human",
        "scope_tag": "e2e-test",
        "schema_version": "1.0.0",
    }


def create_initial_target_profile():
    """Create initial target profile with nmap scan results."""
    return {
        "id": f"target-{SESSION_ID}",
        "session_id": SESSION_ID,
        "hosts": [
            {
                "ip": TARGET_IP,
                "hostname": None,
                "os_guess": "Ubuntu Linux",
                "ttl": 64,
            }
        ],
        "services": [
            {
                "host": TARGET_IP,
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "version": "OpenSSH 7.6p1 Ubuntu 4ubuntu0.5",
                "state": "open",
            },
            {
                "host": TARGET_IP,
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "version": "Apache httpd 2.4.29",
                "state": "open",
                "extra": {"title": "CryptoBank"},
            },
        ],
        "technologies": [
            {"name": "Apache", "version": "2.4.29", "category": "web_server"},
            {"name": "OpenSSH", "version": "7.6p1", "category": "ssh"},
            {"name": "Ubuntu", "version": "unknown", "category": "os"},
        ],
        "created_at": datetime.utcnow().isoformat() + "Z",
        "created_by": "recon_agent",
        "scope_tag": "e2e-test",
        "schema_version": "1.0.0",
    }


def approval_callback(request: ApprovalRequest) -> ApprovalResult:
    """Handle approval requests interactively."""
    print("\n" + "=" * 60)
    print("APPROVAL REQUIRED")
    print("=" * 60)
    print(f"Operation: {request.operation}")
    print(f"Target: {request.target}")
    print(f"Description: {request.description}")
    print(f"Risk Level: {request.risk_level}")
    if request.details:
        print(f"Details: {json.dumps(request.details, indent=2)}")
    print("=" * 60)

    while True:
        response = input("Approve this operation? [y/n]: ").strip().lower()
        if response in ("y", "yes"):
            return ApprovalResult(
                request_id=request.request_id,
                approved=True,
                responded_by="human",
            )
        elif response in ("n", "no"):
            reason = input("Reason for denial (optional): ").strip()
            return ApprovalResult(
                request_id=request.request_id,
                approved=False,
                responded_by="human",
                reason=reason or "Denied by operator",
            )
        print("Please enter 'y' or 'n'")


def main():
    """Run E2E test."""
    print(f"\nPentestAgent E2E Test")
    print(f"Target: {TARGET_IP}")
    print(f"Session: {SESSION_ID}")
    print("-" * 40)

    # Create workspace
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize session
    session_manager = SessionManager(str(WORKSPACE_DIR))
    session_manager.create_session(SESSION_ID)
    session_path = session_manager.get_session_path(SESSION_ID)

    # Initialize stores
    state_store = StateStore(os.path.join(session_path, "state"))
    evidence_ledger = EvidenceLedger(os.path.join(session_path, "evidence"))

    # Write initial state
    state_store.write_json("scope.json", create_initial_scope())
    state_store.write_json("target_profile.json", create_initial_target_profile())

    print(f"\nSession created: {session_path}")
    print(f"Scope: {TARGET_IP}")

    # Store initial nmap evidence
    nmap_output_path = Path("/tmp/nmap_initial_scan.txt")
    if nmap_output_path.exists():
        nmap_output = nmap_output_path.read_text()
        evidence = evidence_ledger.store(
            data=nmap_output,
            source_tool="nmap",
            extension="txt",
            mime_type="text/plain",
            query_params={"target": TARGET_IP, "options": "-sV -sC -T4"},
        )
        print(f"Nmap evidence stored: {evidence['evidence_id']}")

        # Add observation for nmap scan
        state_store.append_jsonl("observations.jsonl", {
            "id": f"obs-nmap-{datetime.utcnow().strftime('%H%M%S')}",
            "type": "port_scan",
            "tool": "nmap",
            "target": TARGET_IP,
            "evidence_id": evidence["evidence_id"],
            "summary": "Initial port scan: SSH(22), HTTP(80) open",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })

    # Create orchestrator config
    config = OrchestratorConfig(
        session_id=SESSION_ID,
        scope_tag="e2e-test",
        approval_timeout_minutes=10,
        consecutive_error_threshold=3,
    )

    # Initialize orchestrator
    orchestrator = Orchestrator(
        state_store=state_store,
        evidence_ledger=evidence_ledger,
        config=config,
        approval_callback=approval_callback,
    )

    # Register mock handlers (in real scenario, these would be actual agents)
    def recon_handler(context):
        print(f"\n[Recon Agent] Running reconnaissance on {TARGET_IP}...")
        return AgentResult(
            agent_type="recon_agent",
            success=True,
            phase_result={
                "targets_found": 1,
                "ports_scanned": 1000,
                "services_found": 2,
                "success": True,
            },
        )

    def enum_handler(context):
        print(f"\n[Enumeration Agent] Enumerating services on {TARGET_IP}...")
        print("  - Checking HTTP service on port 80...")
        print("  - Found: CryptoBank web application")
        return AgentResult(
            agent_type="enumeration_agent",
            success=True,
            phase_result={
                "services_found": 2,
                "endpoints_found": 5,
                "success": True,
            },
        )

    def planner_handler(context):
        print(f"\n[Planner Agent] Analyzing vulnerabilities...")
        print("  - Checking Apache 2.4.29 for known CVEs...")
        print("  - Checking OpenSSH 7.6p1 for known CVEs...")
        return AgentResult(
            agent_type="planner_agent",
            success=True,
            phase_result={
                "plans_created": 2,
                "vuln_candidates": 3,
                "success": True,
            },
        )

    def exploit_handler(context):
        print(f"\n[Exploitation Agent] Preparing exploitation...")
        print("  - Web application testing planned")
        return AgentResult(
            agent_type="exploitation_agent",
            success=True,
            phase_result={"success": True},
        )

    def report_handler(context):
        print(f"\n[Reporting Agent] Generating report...")
        return AgentResult(
            agent_type="reporting_agent",
            success=True,
            phase_result={"success": True},
        )

    orchestrator.register_agent_handler("recon_agent", recon_handler)
    orchestrator.register_agent_handler("enumeration_agent", enum_handler)
    orchestrator.register_agent_handler("planner_agent", planner_handler)
    orchestrator.register_agent_handler("exploitation_agent", exploit_handler)
    orchestrator.register_agent_handler("reporting_agent", report_handler)

    print("\n" + "=" * 40)
    print("Starting Orchestrator Workflow")
    print("=" * 40)

    # Run workflow
    result = orchestrator.run_workflow()

    # Print results
    print("\n" + "=" * 40)
    print("Workflow Complete")
    print("=" * 40)
    print(f"Final Phase: {result['final_phase']}")
    print(f"Total Phases Run: {result['total_phases_run']}")
    print(f"Stopped: {result['stopped']}")

    if result.get("stop_reason"):
        print(f"Stop Reason: {result['stop_reason']}")

    print("\nPhase Results:")
    for phase_result in result.get("results", []):
        status = "OK" if phase_result["success"] else "FAIL"
        print(f"  - {phase_result['phase']}: [{status}] ({phase_result['duration_ms']}ms)")

    print(f"\nSession data saved to: {session_path}")

    return result


if __name__ == "__main__":
    try:
        result = main()
        sys.exit(0 if not result.get("stopped") else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
