"""
Unit tests for StateStore.
"""

import json
import pytest
import tempfile
import shutil
from pathlib import Path

from src.storage.state_store import StateStore, StateVersionError


class TestStateStore:
    """Tests for StateStore class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def state_store(self, temp_dir):
        """Create a StateStore with temporary directory."""
        return StateStore(state_dir=temp_dir)

    # ==================== JSON Operations ====================

    def test_write_and_read_json(self, state_store):
        """Test writing and reading JSON files."""
        data = {"key": "value", "number": 42, "nested": {"a": 1}}
        state_store.write_json("test.json", data)

        read_data = state_store.read_json("test.json")
        assert read_data == data

    def test_read_json_not_found(self, state_store):
        """Test reading nonexistent JSON file raises error."""
        with pytest.raises(FileNotFoundError):
            state_store.read_json("nonexistent.json")

    def test_write_json_overwrites(self, state_store):
        """Test that write_json overwrites existing file."""
        state_store.write_json("test.json", {"old": "data"})
        state_store.write_json("test.json", {"new": "data"})

        data = state_store.read_json("test.json")
        assert data == {"new": "data"}

    def test_json_exists(self, state_store):
        """Test checking if JSON file exists."""
        assert state_store.json_exists("test.json") is False

        state_store.write_json("test.json", {})

        assert state_store.json_exists("test.json") is True

    def test_json_unicode(self, state_store):
        """Test JSON with unicode characters."""
        data = {"message": "Hello", "emoji": "🔒"}
        state_store.write_json("unicode.json", data)

        read_data = state_store.read_json("unicode.json")
        assert read_data == data

    # ==================== JSONL Operations ====================

    def test_append_and_read_jsonl(self, state_store):
        """Test appending and reading JSONL files."""
        record1 = {"id": 1, "data": "first"}
        record2 = {"id": 2, "data": "second"}

        state_store.append_jsonl("test.jsonl", record1)
        state_store.append_jsonl("test.jsonl", record2)

        records = state_store.read_jsonl("test.jsonl")
        assert len(records) == 2
        assert records[0] == record1
        assert records[1] == record2

    def test_read_jsonl_empty(self, state_store, temp_dir):
        """Test reading empty JSONL file."""
        # Create empty file
        (Path(temp_dir) / "empty.jsonl").touch()

        records = state_store.read_jsonl("empty.jsonl")
        assert records == []

    def test_read_jsonl_not_found(self, state_store):
        """Test reading nonexistent JSONL file returns empty list."""
        records = state_store.read_jsonl("nonexistent.jsonl")
        assert records == []

    def test_read_jsonl_tail(self, state_store):
        """Test reading last N records from JSONL file."""
        for i in range(10):
            state_store.append_jsonl("test.jsonl", {"id": i})

        tail = state_store.read_jsonl_tail("test.jsonl", n=3)

        assert len(tail) == 3
        assert tail[0]["id"] == 7
        assert tail[1]["id"] == 8
        assert tail[2]["id"] == 9

    def test_count_jsonl(self, state_store):
        """Test counting records in JSONL file."""
        for i in range(5):
            state_store.append_jsonl("test.jsonl", {"id": i})

        count = state_store.count_jsonl("test.jsonl")
        assert count == 5

    def test_count_jsonl_not_found(self, state_store):
        """Test counting nonexistent JSONL file returns 0."""
        count = state_store.count_jsonl("nonexistent.jsonl")
        assert count == 0

    # ==================== State Version Management ====================

    def test_get_version_initial(self, state_store):
        """Test initial version is 0."""
        version = state_store.get_version()
        assert version == 0

    def test_increment_version(self, state_store):
        """Test incrementing state version."""
        # Initialize version file
        state_store.write_json("state_version.json", {"version": 0, "history": []})

        new_version = state_store.increment_version(
            reason="test increment",
            actor="test"
        )

        assert new_version == 1
        assert state_store.get_version() == 1

    def test_increment_version_multiple(self, state_store):
        """Test multiple version increments."""
        state_store.write_json("state_version.json", {"version": 0, "history": []})

        state_store.increment_version(reason="first", actor="test")
        state_store.increment_version(reason="second", actor="test")
        state_store.increment_version(reason="third", actor="test")

        assert state_store.get_version() == 3

    def test_check_version(self, state_store):
        """Test checking version match."""
        state_store.write_json("state_version.json", {"version": 5, "history": []})

        assert state_store.check_version(5) is True
        assert state_store.check_version(4) is False
        assert state_store.check_version(6) is False

    def test_validate_version_success(self, state_store):
        """Test version validation passes on match."""
        state_store.write_json("state_version.json", {"version": 5, "history": []})

        # Should not raise
        state_store.validate_version(5)

    def test_validate_version_mismatch(self, state_store):
        """Test version validation raises on mismatch."""
        state_store.write_json("state_version.json", {"version": 5, "history": []})

        with pytest.raises(StateVersionError, match="version conflict"):
            state_store.validate_version(3)

    def test_get_version_history(self, state_store):
        """Test getting version history."""
        state_store.write_json("state_version.json", {"version": 0, "history": []})

        state_store.increment_version(reason="first", actor="actor1")
        state_store.increment_version(reason="second", actor="actor2")

        history = state_store.get_version_history(limit=10)

        assert len(history) == 2
        # Newest first
        assert history[0]["version"] == 2
        assert history[0]["reason"] == "second"
        assert history[1]["version"] == 1
        assert history[1]["reason"] == "first"

    def test_version_history_limit(self, state_store):
        """Test version history respects limit."""
        state_store.write_json("state_version.json", {"version": 0, "history": []})

        for i in range(10):
            state_store.increment_version(reason=f"change {i}", actor="test")

        history = state_store.get_version_history(limit=3)
        assert len(history) == 3

    # ==================== Context Bundle Operations ====================

    def test_save_context_bundle(self, state_store):
        """Test saving a context bundle."""
        bundle = {
            "session_id": "test-session",
            "state_version": 1,
            "scope": {"targets": ["192.168.1.1"]},
        }

        path = state_store.save_context_bundle("recon", bundle)

        assert path is not None
        assert "recon" in path
        assert path.endswith(".json")

    def test_save_context_bundle_with_timestamp(self, state_store):
        """Test saving a context bundle with custom timestamp."""
        bundle = {"data": "test"}

        path = state_store.save_context_bundle(
            "enumeration",
            bundle,
            timestamp="20231215_120000_000000"
        )

        assert "20231215_120000_000000" in path

    def test_list_context_bundles(self, state_store):
        """Test listing context bundles."""
        state_store.save_context_bundle("planner", {"id": 1}, timestamp="20231215_100000")
        state_store.save_context_bundle("planner", {"id": 2}, timestamp="20231215_110000")
        state_store.save_context_bundle("planner", {"id": 3}, timestamp="20231215_120000")

        bundles = state_store.list_context_bundles("planner")

        assert len(bundles) == 3
        # Newest first
        assert bundles[0] == "20231215_120000"
        assert bundles[1] == "20231215_110000"
        assert bundles[2] == "20231215_100000"

    def test_list_context_bundles_empty(self, state_store):
        """Test listing bundles for agent with no bundles."""
        bundles = state_store.list_context_bundles("exploitation")
        assert bundles == []

    def test_get_latest_context_bundle(self, state_store):
        """Test getting the latest context bundle."""
        state_store.save_context_bundle("recon", {"id": 1}, timestamp="20231215_100000")
        state_store.save_context_bundle("recon", {"id": 2}, timestamp="20231215_110000")
        state_store.save_context_bundle("recon", {"id": 3}, timestamp="20231215_120000")

        latest = state_store.get_latest_context_bundle("recon")

        assert latest is not None
        assert latest["id"] == 3

    def test_get_latest_context_bundle_none(self, state_store):
        """Test getting latest bundle when none exist."""
        latest = state_store.get_latest_context_bundle("enumeration")
        assert latest is None
