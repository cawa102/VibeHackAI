"""
State Store for PentestAgent.

Provides JSON and JSONL file operations for session state management.
Includes state versioning for optimistic locking.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union


class StateVersionError(Exception):
    """Raised when state version conflict is detected."""
    pass


class StateStore:
    """
    Manages session state files (JSON and JSONL).

    Provides:
    - JSON file read/write operations
    - JSONL (JSON Lines) append/read operations
    - State version management for optimistic locking
    """

    def __init__(self, state_dir: Union[str, Path]):
        """
        Initialize StateStore.

        Args:
            state_dir: Directory containing state files.
        """
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)

    # ==================== JSON Operations ====================

    def read_json(self, filename: str) -> dict:
        """
        Read a JSON file from state directory.

        Args:
            filename: Name of the JSON file (e.g., "scope.json").

        Returns:
            Parsed JSON data as dictionary.

        Raises:
            FileNotFoundError: If file does not exist.
            json.JSONDecodeError: If file contains invalid JSON.
        """
        file_path = self.state_dir / filename
        return json.loads(file_path.read_text(encoding="utf-8"))

    def write_json(self, filename: str, data: dict) -> None:
        """
        Write data to a JSON file in state directory.

        Args:
            filename: Name of the JSON file.
            data: Dictionary to serialize as JSON.
        """
        file_path = self.state_dir / filename
        file_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

    def json_exists(self, filename: str) -> bool:
        """Check if a JSON file exists."""
        return (self.state_dir / filename).exists()

    # ==================== JSONL Operations ====================

    def append_jsonl(self, filename: str, record: dict) -> None:
        """
        Append a record to a JSONL file (append-only).

        Args:
            filename: Name of the JSONL file (e.g., "observations.jsonl").
            record: Dictionary to append as a JSON line.
        """
        file_path = self.state_dir / filename

        # Ensure file exists
        if not file_path.exists():
            file_path.touch()

        # Append record with newline
        with file_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def read_jsonl(self, filename: str) -> list[dict]:
        """
        Read all records from a JSONL file.

        Args:
            filename: Name of the JSONL file.

        Returns:
            List of parsed records.
        """
        file_path = self.state_dir / filename

        if not file_path.exists():
            return []

        records = []
        with file_path.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:  # Skip empty lines
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        raise json.JSONDecodeError(
                            f"Invalid JSON at line {line_num}: {e.msg}",
                            e.doc,
                            e.pos
                        )

        return records

    def read_jsonl_tail(self, filename: str, n: int = 10) -> list[dict]:
        """
        Read the last N records from a JSONL file.

        Args:
            filename: Name of the JSONL file.
            n: Number of records to retrieve.

        Returns:
            List of the last N records.
        """
        records = self.read_jsonl(filename)
        return records[-n:] if records else []

    def count_jsonl(self, filename: str) -> int:
        """
        Count records in a JSONL file.

        Args:
            filename: Name of the JSONL file.

        Returns:
            Number of records.
        """
        file_path = self.state_dir / filename

        if not file_path.exists():
            return 0

        count = 0
        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1

        return count

    # ==================== State Version Management ====================

    def get_version(self) -> int:
        """
        Get current state version.

        Returns:
            Current state version number.
        """
        try:
            data = self.read_json("state_version.json")
            return data.get("version", 0)
        except FileNotFoundError:
            return 0

    def increment_version(self, reason: str = "", actor: str = "system") -> int:
        """
        Increment state version and record in history.

        Args:
            reason: Description of why version was incremented.
            actor: Who/what triggered the increment.

        Returns:
            New state version number.
        """
        try:
            data = self.read_json("state_version.json")
        except FileNotFoundError:
            data = {"version": 0, "history": []}

        new_version = data.get("version", 0) + 1

        # Add to history
        history_entry = {
            "version": new_version,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "reason": reason,
            "actor": actor,
        }

        if "history" not in data:
            data["history"] = []

        data["history"].append(history_entry)
        data["version"] = new_version

        # Keep only last 100 history entries
        if len(data["history"]) > 100:
            data["history"] = data["history"][-100:]

        self.write_json("state_version.json", data)

        return new_version

    def check_version(self, expected_version: int) -> bool:
        """
        Check if current version matches expected version.

        Args:
            expected_version: The expected state version.

        Returns:
            True if versions match, False otherwise.
        """
        return self.get_version() == expected_version

    def validate_version(self, expected_version: int) -> None:
        """
        Validate state version, raising exception on mismatch.

        Args:
            expected_version: The expected state version.

        Raises:
            StateVersionError: If versions do not match.
        """
        current_version = self.get_version()
        if current_version != expected_version:
            raise StateVersionError(
                f"State version conflict: expected {expected_version}, "
                f"current is {current_version}"
            )

    def get_version_history(self, limit: int = 10) -> list[dict]:
        """
        Get recent state version history.

        Args:
            limit: Maximum number of history entries to return.

        Returns:
            List of history entries, newest first.
        """
        try:
            data = self.read_json("state_version.json")
            history = data.get("history", [])
            return list(reversed(history[-limit:]))
        except FileNotFoundError:
            return []

    # ==================== Context Bundle Operations ====================

    def save_context_bundle(
        self,
        agent_type: str,
        bundle: dict,
        timestamp: Optional[str] = None
    ) -> str:
        """
        Save a context bundle for an agent.

        Args:
            agent_type: Type of agent (recon/enumeration/planner/exploitation).
            bundle: Context bundle data.
            timestamp: Optional timestamp. If not provided, uses current time.

        Returns:
            Path to saved bundle file.
        """
        if timestamp is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")

        bundle_dir = self.state_dir / "context_bundles" / agent_type
        bundle_dir.mkdir(parents=True, exist_ok=True)

        bundle_file = bundle_dir / f"{timestamp}.json"
        bundle_file.write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        return str(bundle_file)

    def list_context_bundles(self, agent_type: str) -> list[str]:
        """
        List context bundles for an agent type.

        Args:
            agent_type: Type of agent.

        Returns:
            List of bundle timestamps, newest first.
        """
        bundle_dir = self.state_dir / "context_bundles" / agent_type

        if not bundle_dir.exists():
            return []

        bundles = [
            f.stem for f in bundle_dir.iterdir()
            if f.suffix == ".json"
        ]

        return sorted(bundles, reverse=True)

    def get_latest_context_bundle(self, agent_type: str) -> Optional[dict]:
        """
        Get the most recent context bundle for an agent type.

        Args:
            agent_type: Type of agent.

        Returns:
            Bundle data or None if no bundles exist.
        """
        bundles = self.list_context_bundles(agent_type)

        if not bundles:
            return None

        bundle_file = (
            self.state_dir / "context_bundles" / agent_type / f"{bundles[0]}.json"
        )

        return json.loads(bundle_file.read_text(encoding="utf-8"))
