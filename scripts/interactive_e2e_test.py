#!/usr/bin/env python3
"""
Interactive E2E Test Script for PentestAgent.

Demonstrates the step-by-step workflow:
1. User provides IP
2. Planner creates initial plan
3. Orchestrator proposes plan to user
4. User approves/modifies action
5. Orchestrator assigns task to agent
6. Agent returns results
7. Orchestrator feeds results to Planner
8. Planner updates plan
9. Loop continues until completion
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.orchestrator.orchestrator import Orchestrator, OrchestratorConfig, AgentResult
from src.orchestrator.workflow import (
    InteractiveWorkflow,
    ExecutionPlan,
    PlanStep,
    TaskType,
    TaskStatus,
    WorkflowPhase,
    UserProposal,
    UserResponse,
    AgentTaskResult,
)
from src.storage.state_store import StateStore
from src.storage.evidence_ledger import EvidenceLedger
from src.storage.session_manager import SessionManager
from src.cli.interactive_cli import InteractiveCLI, user_interaction_callback


# Configuration
WORKSPACE_DIR = project_root / "workspace"


def run_nmap_scan(target: str, options: str = "-sV -sC -T4") -> str:
    """Run actual nmap scan and return results."""
    try:
        cmd = f"nmap {options} {target}"
        result = subprocess.run(
            cmd.split(),
            capture_output=True,
            text=True,
            timeout=300,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Scan timed out"
    except Exception as e:
        return f"Scan error: {e}"


def create_recon_handler(target_ip: str, evidence_ledger: EvidenceLedger):
    """Create handler for reconnaissance agent."""
    def recon_handler(context):
        print(f"\n[Recon Agent] Performing reconnaissance on {target_ip}...")

        # Run actual nmap scan
        nmap_output = run_nmap_scan(target_ip, "-sV -sC -T4 -p1-1000")

        # Store evidence
        evidence = evidence_ledger.store(
            data=nmap_output,
            source_tool="nmap",
            extension="txt",
            mime_type="text/plain",
            query_params={"target": target_ip, "options": "-sV -sC -T4 -p1-1000"},
        )
        print(f"  Evidence stored: {evidence['evidence_id']}")

        # Parse results (simplified)
        services_found = nmap_output.count("/tcp") + nmap_output.count("/udp")
        ports_open = nmap_output.lower().count("open")

        print(f"  Found {ports_open} open ports, {services_found} services")

        return AgentResult(
            agent_type="recon_agent",
            success=True,
            phase_result={
                "services_found": services_found,
                "ports_open": ports_open,
                "evidence_id": evidence["evidence_id"],
                "success": True,
            },
        )

    return recon_handler


def create_enumeration_handler(target_ip: str, evidence_ledger: EvidenceLedger):
    """Create handler for enumeration agent."""
    def enumeration_handler(context):
        print(f"\n[Enumeration Agent] Enumerating services on {target_ip}...")

        # Run vulnerability scripts
        vuln_output = run_nmap_scan(target_ip, "--script=vuln -p22,80")

        # Store evidence
        evidence = evidence_ledger.store(
            data=vuln_output,
            source_tool="nmap_vuln",
            extension="txt",
            mime_type="text/plain",
            query_params={"target": target_ip, "scripts": "vuln"},
        )
        print(f"  Evidence stored: {evidence['evidence_id']}")

        # Check for HTTP
        http_content = ""
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://{target_ip}/", timeout=10) as response:
                http_content = response.read().decode("utf-8", errors="ignore")[:5000]
        except Exception as e:
            print(f"  HTTP fetch error: {e}")

        # Count CVEs found
        cve_count = vuln_output.upper().count("CVE-")
        vulns_found = cve_count if cve_count > 0 else vuln_output.lower().count("vulnerable")

        print(f"  Found {vulns_found} potential vulnerabilities")

        return AgentResult(
            agent_type="enumeration_agent",
            success=True,
            phase_result={
                "vulnerabilities_found": vulns_found,
                "endpoints_found": 3 if http_content else 0,
                "evidence_id": evidence["evidence_id"],
                "success": True,
            },
        )

    return enumeration_handler


def create_planner_handler():
    """Create handler for planner agent."""
    def planner_handler(context):
        print("\n[Planner Agent] Analyzing vulnerabilities and creating plan...")

        # Simulate vulnerability analysis
        vuln_candidates = 5
        exploit_candidates = 2
        high_severity = 2

        print(f"  Identified {vuln_candidates} vulnerability candidates")
        print(f"  Found {exploit_candidates} potential exploits")
        print(f"  High/Critical severity: {high_severity}")

        return AgentResult(
            agent_type="planner_agent",
            success=True,
            phase_result={
                "vuln_candidates_found": vuln_candidates,
                "exploit_candidates_found": exploit_candidates,
                "high_severity_vulns": high_severity,
                "execution_plan_created": True,
                "success": True,
            },
        )

    return planner_handler


def create_exploitation_handler(target_ip: str, evidence_ledger: EvidenceLedger):
    """Create handler for exploitation agent."""
    def exploitation_handler(context):
        print(f"\n[Exploitation Agent] Attempting exploitation on {target_ip}...")
        print("  WARNING: This would execute actual exploits in production")

        # Simulated exploitation (safe for testing)
        # In real scenario, this would use Metasploit or other tools

        exploitation_log = f"""
Exploitation Attempt Log
========================
Target: {target_ip}
Timestamp: {datetime.utcnow().isoformat()}Z

[*] Testing SQL injection on /trade/login_auth.php
[*] WAF detected - trying bypass techniques
[!] Standard payloads blocked

[*] Testing CVE-2021-44790 (Apache mod_lua buffer overflow)
[-] Module not enabled

[*] Testing CVE-2018-15473 (SSH user enumeration)
[+] User enumeration possible
[+] Discovered users: root, admin, www-data

[*] Testing default credentials
[+] Found: admin:admin123 (simulated)

Result: Partial success - credential discovery
"""

        # Store evidence
        evidence = evidence_ledger.store(
            data=exploitation_log,
            source_tool="exploitation_agent",
            extension="txt",
            mime_type="text/plain",
            query_params={"target": target_ip},
        )

        print("  Exploitation attempt completed")
        print(f"  Evidence stored: {evidence['evidence_id']}")

        return AgentResult(
            agent_type="exploitation_agent",
            success=True,
            phase_result={
                "exploitation_success": True,
                "method": "Credential discovery via user enumeration",
                "evidence_id": evidence["evidence_id"],
                "findings": [
                    "SSH user enumeration vulnerability",
                    "Weak credentials discovered",
                ],
                "success": True,
            },
        )

    return exploitation_handler


def main():
    """Run interactive E2E test."""
    cli = InteractiveCLI()

    print("\n" + "=" * 60)
    print("PentestAgent Interactive E2E Test")
    print("=" * 60)

    # Get target IP from user
    target_ip = input("\nEnter target IP address: ").strip()
    if not target_ip:
        print("No target IP provided. Exiting.")
        return 1

    # Confirm target
    if not cli.confirm(f"Confirm target: {target_ip}?", default=True):
        print("Cancelled.")
        return 0

    # Create session
    session_id = f"interactive-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
    print(f"\nSession: {session_id}")

    # Initialize storage
    WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
    session_manager = SessionManager(str(WORKSPACE_DIR))
    session_manager.create_session(session_id)
    session_path = session_manager.get_session_path(session_id)

    state_store = StateStore(os.path.join(session_path, "state"))
    evidence_ledger = EvidenceLedger(os.path.join(session_path, "evidence"))

    # Initialize scope
    scope = {
        "id": f"scope-{session_id}",
        "session_id": session_id,
        "targets": [{"type": "ip", "value": target_ip}],
        "allowed_operations": ["scan", "enumerate", "exploit"],
        "created_at": datetime.utcnow().isoformat() + "Z",
        "created_by": "human",
        "scope_tag": "interactive-test",
        "schema_version": "1.0.0",
    }
    state_store.write_json("scope.json", scope)

    # Initialize target profile
    target_profile = {
        "id": f"target-{session_id}",
        "session_id": session_id,
        "hosts": [{"ip": target_ip}],
        "services": [],
        "technologies": [],
        "created_at": datetime.utcnow().isoformat() + "Z",
        "created_by": "user",
        "scope_tag": "interactive-test",
        "schema_version": "1.0.0",
    }
    state_store.write_json("target_profile.json", target_profile)

    # Create orchestrator
    config = OrchestratorConfig(
        session_id=session_id,
        scope_tag="interactive-test",
        approval_timeout_minutes=10,
    )

    orchestrator = Orchestrator(
        state_store=state_store,
        evidence_ledger=evidence_ledger,
        config=config,
    )

    # Register agent handlers
    orchestrator.register_agent_handler(
        "recon_agent",
        create_recon_handler(target_ip, evidence_ledger),
    )
    orchestrator.register_agent_handler(
        "enumeration_agent",
        create_enumeration_handler(target_ip, evidence_ledger),
    )
    orchestrator.register_agent_handler(
        "planner_agent",
        create_planner_handler(),
    )
    orchestrator.register_agent_handler(
        "exploitation_agent",
        create_exploitation_handler(target_ip, evidence_ledger),
    )

    # Create interactive workflow
    workflow = orchestrator.create_interactive_workflow(
        planner_handler=create_planner_handler(),
        user_callback=user_interaction_callback,
    )

    print(f"\nStarting workflow for target: {target_ip}")
    print("-" * 40)

    # Step 1 & 2: Start workflow (planner creates initial plan)
    proposal = workflow.start(target_ip)

    # Main interaction loop
    while proposal is not None:
        # Step 3: Display proposal to user
        cli.display_proposal(proposal)

        # Step 4: Get user response
        response = cli.get_user_response(proposal)

        # Check for stop
        if response.selected_option == "stop":
            cli.display_status(
                WorkflowPhase.STOPPED,
                "Workflow stopped by user",
            )
            break

        # Step 5-9: Process response and continue
        cli.display_status(
            WorkflowPhase.EXECUTING,
            f"Processing: {response.selected_option}",
        )

        proposal = workflow.process_user_response(response)

    # Display final status
    status = workflow.get_status()
    print("\n" + "=" * 60)
    print("Workflow Complete")
    print("=" * 60)
    print(f"Session: {session_id}")
    print(f"Final Phase: {status['phase']}")
    print(f"Session data saved to: {session_path}")

    if status.get("progress"):
        progress = status["progress"]
        print(f"\nProgress:")
        print(f"  Completed: {progress['completed']}/{progress['total']}")
        print(f"  Failed: {progress['failed']}")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
