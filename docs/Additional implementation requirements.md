# VibeHackAI Additional Implementation Requirements (Semi-Automated Interactive Penetration Testing Support Tool)

## 1. Background and Purpose
VibeHackAI is a semi-automated tool where the human (tester) retains absolute authority, safely conducting penetration testing through dialogue with the Orchestrator. AI agents handle the actual work (plan detailing, command execution, evidence collection, report drafting), while humans perform monitoring, approval, and stop decisions.

This request aims to introduce additional implementation (differences) to the current specifications and implementation to satisfy the following operational policies.

---

## 2. Operational Policies to be Satisfied by This Request (Required)
### 2.1 Humans Hold Absolute Authority
- Even when an agent "stops" for safety or policy reasons, it must always report to the human.
- If the human permits, the stopped operation can be resumed/executed with **explicit audit log (human Override)** recorded.

### 2.2 Approval Granularity is "Per Phase Transition"
- Humans approve at the "phase start (proceed to next phase)" level, not individual commands.
- Purpose: Prevent automatic progression in the wrong direction and improve traceability.

### 2.3 Orchestrator Explains "What Will Be Done" in Natural Language (Commands Not Displayed)
- Example human presentation: "Will scan the Target IP to check open ports", etc.
- Actual executed command strings are saved as Evidence for audit/reproducibility, but not displayed to humans in normal UI/output (detailed display only when needed).

### 2.4 Reports are OPTRS/OWASP Style + CVSS Attached
- Findings must have OPTRS/OWASP-aware structure (reproduction steps, impact, remediation, evidence, evaluation).
- CVSS-based evaluation (version and vector) must always be attached.

### 2.5 Exploit Success Proof Allows "Limited File Reading"
- However, the permitted range (maximum bytes, target path restrictions, etc.) is policy-defined, and deviations trigger stop→report→human judgment.

### 2.6 Test Plan File Operated as Single Source of Truth
- Planner creates a test plan file (Test Plan), and subsequent tests proceed based on this plan in principle.
- When Planner reconstructs the plan based on each phase result (Recon/Enum/Exploit), the Test Plan is updated accordingly, and update history is kept in an auditable form.

### 2.7 Created Files are Organized by Target Folder
- To avoid confusion when referencing evidence within the same project, organize by target folder and save within it.

---

## 3. Scope
### 3.1 Target Components
- Orchestrator (state management, phase control, approval, UI/dialogue, audit log)
- Planner (phase plan reconstruction, generation source for natural language explanations)
- Reconnaissance / Enumeration / Exploitation agents
- Schemas (state.json / scope.json / evidence / findings / plan, etc.)
- Report generation (reports/draft.md, etc.)

### 3.2 Non-Targets (Non-Goals for This Request)
- Adding new attack techniques/malware development functions
- Functions that enable testing on unauthorized targets
- Internal implementation modifications of existing external tools (Hexstrike, etc.) (however, settings/guardrail integration is in scope)

---

## 4. Common Definitions (Terminology)
- **Phase**: Units of Planner / Recon / Enum / Exploit.
- **PhaseBrief (For Human Presentation)**: A summary showing "what will be done", "why", "risks", "constraints" for the next phase in natural language. Commands not displayed.
- **PhasePlan (For Execution)**: Abstract plan needed for internal execution. Includes tool selection and constraints.
- **Evidence**: Execution logs, output, screenshot references, hashes, etc. Basis for reproducibility.
- **Override (Human Override Permission)**: Explicit permission to continue by lifting stops/restrictions. Audit log required.

---

## 5. Functional Requirements
### FR-1: Phase Boundary Approval Flow Implementation (Required)
- Orchestrator **must present PhaseBrief to human** before starting each phase and obtain approval/rejection/hold.
- Do not start agent execution for that phase until approved.
- On phase completion, reflect results in state→pass to Planner to reconstruct next PhasePlan→proceed to next phase approval.

**Acceptance Criteria**
- No phase starts without approval.
- All phase starts have approval records (who, when, what was approved).

---

### FR-2: Orchestrator's "Natural Language Summary Presentation (Commands Not Displayed)" Mode (Required)
- Presentation to human is PhaseBrief only (natural language).
- Executed commands and parameters are saved in Evidence/audit log, but not displayed in standard output.
- Provide "Detailed Display (for audit)" toggle in UI/output, allowing reference to commands in Evidence when needed.

**Acceptance Criteria**
- Command strings are not displayed in standard output/UI.
- Commands are saved as evidence, ensuring reproducibility.

---

### FR-3: Stop, Report, and Additional Approval on Policy Escalation (Unexpected High-Risk Operations) (Required)
- During a phase, if high-risk operations not included in PhaseBrief/PhasePlan become necessary (e.g., high-intensity scans, increased invasiveness, file read limit exceeded):
  1) Agent notifies Orchestrator of **Escalation**
  2) Orchestrator stops execution and presents "additional PhaseBrief (difference)" to human
  3) Continue only if human approves (maintain stop if rejected)
- If existing `requires_approval` exists, redefine it as **"escalation flag for deviations"** rather than "per-command approval".

**Acceptance Criteria**
- Deviation operations are not automatically executed; must transition to stop→additional approval flow.

---

### FR-4: Human Absolute Authority (Override) Implemented as System-Wide Recognition (Required)
- When an agent stops for safety reasons:
  - Orchestrator reports stop reason, proposal (alternatives), and impact to human in natural language.
  - Human can choose "continue stop" or "Override and continue".
- When continuing with Override:
  - Save `override_approved=true`, approver, approval time, target operation category, and reason to state/audit log.
  - Attach Override reference ID to Evidence linked to the continued operation.

**Exceptions (Minimum Boundaries Where Override is Not Possible)**
- Clearly destructive operations (data destruction, service stoppage, permanent modification)
- Access to out-of-scope targets
- Actions constituting "malware development/distribution"
(※ The purpose of this tool is vulnerability proof, not malicious code development)

**Acceptance Criteria**
- Stops are always reported to human.
- Audit logs remain when Override is executed, enabling later tracking.

---

### FR-5: Proof-of-Access Policy (Limited File Reading) as Policy (Required)
- Add Proof-of-Access Policy to scope (e.g., scope.json) so Exploitation/Orchestrator can enforce it.
- Example: Maximum file count, maximum bytes, prohibited paths/extensions regex, preferred canary file, etc.
- If excess/deviation is needed, stop via FR-3 Escalation→human judgment.

**Acceptance Criteria**
- File reads are executed only within permitted range.
- Can detect and stop on limit exceeded.

---

### FR-6: Planner Responsibility Enhancement (Per-Phase Decision Making and Explanation Generation) (Required)
- Planner handles not just "Exploit planning" but "entire penetration test planning", **always reconstructing next phase PhasePlan after each phase completion**.
- Add `human_summary` (natural language) to Planner output as the source for Orchestrator's PhaseBrief.
- Clarify design where Planner does not directly execute tools (even if tool is specified, "execution is by other agents").

**Acceptance Criteria**
- After each phase completion, Planner is called and next phase PhasePlan is updated.
- PhaseBrief is generated based on Planner's decision.

---

### FR-7: CVSS Implemented as "version + vector + score" Object (Required)
- Add `cvss` field to VulnCandidate / FindingCandidate, etc. (or replace existing):
  - `version` (e.g., 3.1 / 4.0, etc.)
  - `vector` (e.g., CVSS:3.1/...)
  - `base_score` (numeric)
- CVSS must be displayed for each Finding in report generation.
- Planner **generates and maintains Test Plan file (Test Plan)**.
  - Create initial version at session start (includes scope, purpose, phase sequence, expected methods, constraints, stop conditions, evidence policy).
  - After each phase completion, reflect results and update priorities, next phase purpose, safety constraints, unresolved issues.
  - Plan updates are done via difference (Patch), and update history (who/when/what/why) is kept as audit log.
- When approving phases, Orchestrator presents **Test Plan "current update differences (change summary)"** alongside PhaseBrief to human (without displaying commands).

**Acceptance Criteria**
- All final Findings have CVSS (version, vector, score) attached.
- Handling of unconfirmed items (provisional/needs confirmation) is also stated in report.
- Test Plan file is generated at session start.
- Test Plan is updated after each phase completion, and change history is trackable.
- At next phase approval, Test Plan change summary is presented to human.

---

### FR-8: OPTRS/OWASP Style Report Output (Required)
- Output to `reports/draft.md` (or equivalent) with the following structure:
  - Executive Summary (overview, scope, key findings)
  - Methodology (phases, tools used, approval model)
  - Findings (each vulnerability: overview, impact, reproduction steps, Evidence, CVSS, remediation, verification conditions)
  - Appendix (detailed log references, Evidence ID list, (optional) command details)
- Commands are not included in the main text by standard; reference in Appendix (or Evidence ID only).

**Acceptance Criteria**
- Draft conforming to above structure is auto-generated.
- Findings are linked to Evidence IDs.

---

## 6. Data Model / Schema Changes (Key Points)
The following are "additions/changes", but implementation should be reviewed. Actual file names should match current implementation.

1) `phase_plan` (new or extended)
- `phase`, `objective`, `human_summary[]`, `constraints{...}`, `risk_notes[]`

2) `phase_brief` (generated: may be saved)
- `phase_to_approve`, `planned_actions[]`, `risk_notes[]`, `safety_limits{...}`, `evidence_policy`

3) `approval_log` (new)
- `phase`, `brief_id`, `approved_by`, `approved_at`, `decision`, `notes`

4) `override_log` (new)
- `override_id`, `reason`, `approved_by`, `approved_at`, `category`, `linked_evidence_ids[]`, `linked_phase`

5) `proof_of_access_policy` (scope extension)
- `allow_file_read`, `max_bytes`, `max_files`, `disallow_paths_regex[]`, `prefer_canary_file`

6) `cvss` (Finding/Vuln extension)
- `{version, vector, base_score}`

7) `test_plan` (new: plan file)
- `plan_id`, `version`, `updated_at`, `updated_by`
- `scope_summary`, `objectives`, `assumptions`, `constraints`, `stop_conditions`
- `phase_sequence[]` (phase order and purpose)
- `open_questions[]`, `risks[]`
- `change_log[]` (difference summary, reason, related Evidence/Findings)

---

## 7. UI/Dialogue Specification (Orchestrator)
- Standard: Natural language only (PhaseBrief)
- Option: "Detailed display" toggle to view Evidence (including commands)
- Stop events (AgentStop/Escalation) must always notify human and present options:
  - Stop (maintain stop)
  - Additional approval (approve difference PhaseBrief and continue)
  - Override (only for permitted categories)

---

## 8. Audit, Log, and Traceability Requirements
- All phase approvals, stops, and Overrides must be kept in audit log (time, actor, reason, related Evidence)
- Reports must have linkable structure to evidence via Evidence ID

---

## 9. Test Requirements (Acceptance Test Perspectives)
The following scenarios must be verifiable automatically/manually.

1) Phase start does not run without approval
2) When deviation operation is requested during phase, transitions to stop→difference approval
3) Agent stop is always reported, and Override/continue stop can be selected
4) When Override is executed, audit log and Evidence are linked
5) Proof-of-Access Policy limit exceeded is blocked
6) Report outputs CVSS version/vector/score
7) Report meets OPTRS/OWASP style structure

End
