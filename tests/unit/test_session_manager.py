"""
Unit tests for SessionManager.
"""

import json
import pytest
import tempfile
import shutil
from pathlib import Path

from src.storage.session_manager import SessionManager


class TestSessionManager:
    """Tests for SessionManager class."""

    @pytest.fixture
    def temp_workspace(self):
        """Create a temporary workspace directory."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def session_manager(self, temp_workspace):
        """Create a SessionManager with temporary workspace."""
        return SessionManager(workspace_root=temp_workspace)

    def test_create_session_generates_uuid(self, session_manager):
        """Test that create_session generates a valid UUID."""
        session_id = session_manager.create_session()

        assert session_id is not None
        assert len(session_id) == 36  # UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        assert session_manager.session_exists(session_id)

    def test_create_session_with_custom_id(self, session_manager):
        """Test creating a session with a custom ID."""
        custom_id = "test-session-001"
        session_id = session_manager.create_session(session_id=custom_id)

        assert session_id == custom_id
        assert session_manager.session_exists(custom_id)

    def test_create_session_duplicate_raises_error(self, session_manager):
        """Test that creating a duplicate session raises ValueError."""
        session_id = session_manager.create_session()

        with pytest.raises(ValueError, match="Session already exists"):
            session_manager.create_session(session_id=session_id)

    def test_create_session_initializes_directory_structure(self, session_manager):
        """Test that session creation initializes the correct directory structure."""
        session_id = session_manager.create_session()
        session_path = session_manager.get_session_path(session_id)

        # Check state directories
        assert (session_path / "state").is_dir()
        assert (session_path / "state" / "context_bundles").is_dir()
        assert (session_path / "state" / "context_bundles" / "recon").is_dir()
        assert (session_path / "state" / "context_bundles" / "enumeration").is_dir()
        assert (session_path / "state" / "context_bundles" / "planner").is_dir()
        assert (session_path / "state" / "context_bundles" / "exploitation").is_dir()

        # Check other directories
        assert (session_path / "evidence").is_dir()
        assert (session_path / "cache").is_dir()
        assert (session_path / "cache" / "cve").is_dir()
        assert (session_path / "cache" / "snyk").is_dir()
        assert (session_path / "cache" / "git").is_dir()
        assert (session_path / "reports").is_dir()

    def test_create_session_initializes_state_files(self, session_manager):
        """Test that session creation initializes state files."""
        session_id = session_manager.create_session()
        session_path = session_manager.get_session_path(session_id)
        state_path = session_path / "state"

        # Check JSON files exist and are valid
        for filename in ["scope.json", "target_profile.json", "candidates_vuln.json",
                         "candidates_exploit.json", "execution_plans.json",
                         "findings.json", "state_version.json"]:
            file_path = state_path / filename
            assert file_path.exists(), f"{filename} should exist"
            data = json.loads(file_path.read_text())
            assert isinstance(data, dict), f"{filename} should contain a dict"

        # Check JSONL files exist
        for filename in ["execution_results.jsonl", "observations.jsonl",
                         "decision_traces.jsonl"]:
            assert (state_path / filename).exists(), f"{filename} should exist"

    def test_get_session_path_nonexistent_raises_error(self, session_manager):
        """Test that get_session_path raises ValueError for nonexistent session."""
        with pytest.raises(ValueError, match="Session not found"):
            session_manager.get_session_path("nonexistent-session")

    def test_list_sessions_empty(self, session_manager):
        """Test list_sessions returns empty list when no sessions exist."""
        sessions = session_manager.list_sessions()
        assert sessions == []

    def test_list_sessions_returns_all_sessions(self, session_manager):
        """Test list_sessions returns all created sessions."""
        session1 = session_manager.create_session()
        session2 = session_manager.create_session()
        session3 = session_manager.create_session()

        sessions = session_manager.list_sessions()

        assert len(sessions) == 3
        session_ids = [s["id"] for s in sessions]
        assert session1 in session_ids
        assert session2 in session_ids
        assert session3 in session_ids

    def test_list_sessions_includes_metadata(self, session_manager):
        """Test list_sessions includes session metadata."""
        session_id = session_manager.create_session()
        sessions = session_manager.list_sessions()

        assert len(sessions) == 1
        session = sessions[0]
        assert session["id"] == session_id
        assert "created_at" in session
        assert "state_version" in session
        assert session["state_version"] == 0

    def test_delete_session(self, session_manager):
        """Test deleting a session."""
        session_id = session_manager.create_session()
        assert session_manager.session_exists(session_id)

        session_manager.delete_session(session_id)

        assert not session_manager.session_exists(session_id)

    def test_delete_session_nonexistent_raises_error(self, session_manager):
        """Test deleting nonexistent session raises ValueError."""
        with pytest.raises(ValueError, match="Session not found"):
            session_manager.delete_session("nonexistent-session")

    def test_get_state_store(self, session_manager):
        """Test getting StateStore for a session."""
        session_id = session_manager.create_session()
        state_store = session_manager.get_state_store(session_id)

        assert state_store is not None
        # Verify it can read initialized files
        data = state_store.read_json("scope.json")
        assert "targets" in data

    def test_get_evidence_ledger(self, session_manager):
        """Test getting EvidenceLedger for a session."""
        session_id = session_manager.create_session()
        evidence_ledger = session_manager.get_evidence_ledger(session_id)

        assert evidence_ledger is not None
        # Verify it's pointing to the right directory
        assert evidence_ledger.list_evidence() == []

    def test_get_cache_store(self, session_manager):
        """Test getting CacheStore for a session."""
        session_id = session_manager.create_session()
        cache_store = session_manager.get_cache_store(session_id)

        assert cache_store is not None
        # Verify it can store and retrieve data
        cache_store.set("test", "query", {"result": "data"})
        assert cache_store.get("test", "query") == {"result": "data"}
