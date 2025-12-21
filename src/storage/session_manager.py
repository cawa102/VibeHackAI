"""
Session Manager for PentestAgent.

Manages session lifecycle including creation, directory structure initialization,
and session listing.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from .state_store import StateStore
from .evidence_ledger import EvidenceLedger
from .cache_store import CacheStore


class SessionManager:
    """
    Manages pentest sessions and their workspace directories.

    Each session has a unique ID and a dedicated directory structure containing:
    - state/: JSON files for session state
    - evidence/: Raw evidence files with metadata
    - cache/: Query result cache
    - reports/: Generated reports
    """

    # Directory structure template
    STATE_DIRS = [
        "state",
        "state/context_bundles",
        "state/context_bundles/recon",
        "state/context_bundles/enumeration",
        "state/context_bundles/planner",
        "state/context_bundles/exploitation",
    ]

    OTHER_DIRS = [
        "evidence",
        "cache",
        "cache/cve",
        "cache/snyk",
        "cache/git",
        "reports",
    ]

    # Initial state files
    INITIAL_STATE_FILES = {
        "scope.json": {"targets": [], "allowed_operations": [], "expires_at": None},
        "target_profile.json": {"hosts": [], "services": [], "technologies": []},
        "candidates_vuln.json": {"candidates": []},
        "candidates_exploit.json": {"candidates": []},
        "execution_plans.json": {"plans": []},
        "findings.json": {"findings": []},
        "state_version.json": {"version": 0, "history": []},
    }

    # JSONL files (append-only)
    JSONL_FILES = [
        "execution_results.jsonl",
        "observations.jsonl",
        "decision_traces.jsonl",
    ]

    def __init__(self, workspace_root: str = "./workspace"):
        """
        Initialize SessionManager.

        Args:
            workspace_root: Root directory for all session workspaces.
        """
        self.workspace_root = Path(workspace_root).resolve()
        self.sessions_dir = self.workspace_root / "sessions"
        self._ensure_workspace_exists()

    def _ensure_workspace_exists(self) -> None:
        """Create workspace root directory if it doesn't exist."""
        self.sessions_dir.mkdir(parents=True, exist_ok=True)

    def create_session(self, session_id: Optional[str] = None) -> str:
        """
        Create a new session with initialized directory structure.

        Args:
            session_id: Optional custom session ID. If not provided, generates UUID v4.

        Returns:
            The session ID of the created session.

        Raises:
            ValueError: If the session ID already exists.
        """
        if session_id is None:
            session_id = str(uuid.uuid4())

        session_path = self.sessions_dir / session_id

        if session_path.exists():
            raise ValueError(f"Session already exists: {session_id}")

        # Create directory structure
        for dir_name in self.STATE_DIRS + self.OTHER_DIRS:
            (session_path / dir_name).mkdir(parents=True, exist_ok=True)

        # Initialize state files
        state_store = StateStore(session_path / "state")
        for filename, initial_data in self.INITIAL_STATE_FILES.items():
            state_store.write_json(filename, initial_data)

        # Create empty JSONL files
        for filename in self.JSONL_FILES:
            (session_path / "state" / filename).touch()

        # Create initial report placeholder
        (session_path / "reports" / "draft.md").write_text(
            f"# Pentest Report - Session {session_id}\n\n"
            f"Created: {datetime.utcnow().isoformat()}Z\n\n"
            "## Findings\n\n*No findings yet.*\n"
        )

        return session_id

    def get_session_path(self, session_id: str) -> Path:
        """
        Get the path to a session's workspace directory.

        Args:
            session_id: The session ID.

        Returns:
            Path to the session directory.

        Raises:
            ValueError: If the session does not exist.
        """
        session_path = self.sessions_dir / session_id
        if not session_path.exists():
            raise ValueError(f"Session not found: {session_id}")
        return session_path

    def session_exists(self, session_id: str) -> bool:
        """Check if a session exists."""
        return (self.sessions_dir / session_id).exists()

    def list_sessions(self) -> list[dict]:
        """
        List all sessions with basic metadata.

        Returns:
            List of session info dictionaries containing:
            - id: Session ID
            - created_at: Creation timestamp (from directory mtime)
            - state_version: Current state version
        """
        sessions = []

        if not self.sessions_dir.exists():
            return sessions

        for session_dir in self.sessions_dir.iterdir():
            if session_dir.is_dir():
                session_info = {
                    "id": session_dir.name,
                    "created_at": datetime.fromtimestamp(
                        session_dir.stat().st_ctime
                    ).isoformat(),
                    "state_version": 0,
                }

                # Try to read state version
                version_file = session_dir / "state" / "state_version.json"
                if version_file.exists():
                    try:
                        import json
                        data = json.loads(version_file.read_text())
                        session_info["state_version"] = data.get("version", 0)
                    except (json.JSONDecodeError, KeyError):
                        pass

                sessions.append(session_info)

        # Sort by creation time, newest first
        sessions.sort(key=lambda x: x["created_at"], reverse=True)
        return sessions

    def delete_session(self, session_id: str) -> None:
        """
        Delete a session and all its data.

        WARNING: This permanently deletes all session data including evidence.

        Args:
            session_id: The session ID to delete.

        Raises:
            ValueError: If the session does not exist.
        """
        session_path = self.get_session_path(session_id)

        import shutil
        shutil.rmtree(session_path)

    def get_state_store(self, session_id: str) -> StateStore:
        """Get a StateStore instance for the session."""
        session_path = self.get_session_path(session_id)
        return StateStore(session_path / "state")

    def get_evidence_ledger(self, session_id: str) -> EvidenceLedger:
        """Get an EvidenceLedger instance for the session."""
        session_path = self.get_session_path(session_id)
        return EvidenceLedger(session_path / "evidence")

    def get_cache_store(self, session_id: str) -> CacheStore:
        """Get a CacheStore instance for the session."""
        session_path = self.get_session_path(session_id)
        return CacheStore(session_path / "cache")
