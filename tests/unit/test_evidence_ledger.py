"""
Unit tests for EvidenceLedger.
"""

import json
import pytest
import tempfile
import shutil
from pathlib import Path

from src.storage.evidence_ledger import (
    EvidenceLedger,
    EvidenceIntegrityError,
    EvidenceNotFoundError,
    EvidenceDeletionError,
)


class TestEvidenceLedger:
    """Tests for EvidenceLedger class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def ledger(self, temp_dir):
        """Create an EvidenceLedger with temporary directory."""
        return EvidenceLedger(evidence_dir=temp_dir)

    def test_store_bytes(self, ledger):
        """Test storing binary evidence."""
        data = b"test binary data"
        meta = ledger.store(
            data=data,
            source_tool="test_tool",
            extension="bin",
        )

        assert "evidence_id" in meta
        assert meta["evidence_id"].startswith("ev-")
        assert "sha256" in meta
        assert meta["size_bytes"] == len(data)
        assert meta["source_tool"] == "test_tool"
        assert meta["extension"] == "bin"

    def test_store_string(self, ledger):
        """Test storing string evidence."""
        data = "test string data"
        meta = ledger.store(
            data=data,
            source_tool="test_tool",
            extension="txt",
        )

        assert meta["size_bytes"] == len(data.encode("utf-8"))

    def test_store_with_metadata(self, ledger):
        """Test storing evidence with full metadata."""
        data = b"test data"
        meta = ledger.store(
            data=data,
            source_tool="nmap",
            extension="xml",
            query_params={"target": "192.168.1.1", "ports": "1-1000"},
            response_code=0,
            mime_type="application/xml",
            additional_meta={"scan_type": "SYN"},
        )

        assert meta["query_params"] == {"target": "192.168.1.1", "ports": "1-1000"}
        assert meta["response_code"] == 0
        assert meta["mime_type"] == "application/xml"
        assert meta["additional"]["scan_type"] == "SYN"

    def test_store_creates_files(self, ledger, temp_dir):
        """Test that store creates raw and meta files."""
        data = b"test data"
        meta = ledger.store(data=data, source_tool="test", extension="bin")

        evidence_path = Path(temp_dir) / meta["evidence_id"]
        assert evidence_path.is_dir()
        assert (evidence_path / "raw.bin").exists()
        assert (evidence_path / "meta.json").exists()

    def test_get_evidence(self, ledger):
        """Test retrieving evidence metadata."""
        data = b"test data"
        stored_meta = ledger.store(data=data, source_tool="test", extension="bin")

        retrieved_meta = ledger.get(stored_meta["evidence_id"])

        assert retrieved_meta["evidence_id"] == stored_meta["evidence_id"]
        assert retrieved_meta["sha256"] == stored_meta["sha256"]

    def test_get_evidence_not_found(self, ledger):
        """Test getting nonexistent evidence raises error."""
        with pytest.raises(EvidenceNotFoundError, match="Evidence not found"):
            ledger.get("nonexistent-evidence-id")

    def test_get_raw_data(self, ledger):
        """Test retrieving raw evidence data."""
        original_data = b"test binary data for retrieval"
        meta = ledger.store(data=original_data, source_tool="test", extension="bin")

        retrieved_data = ledger.get_raw_data(meta["evidence_id"])

        assert retrieved_data == original_data

    def test_sha256_integrity_check(self, ledger, temp_dir):
        """Test that integrity check detects tampering."""
        data = b"original data"
        meta = ledger.store(data=data, source_tool="test", extension="bin")

        # Tamper with the raw file
        raw_path = Path(temp_dir) / meta["evidence_id"] / "raw.bin"
        raw_path.write_bytes(b"tampered data")

        with pytest.raises(EvidenceIntegrityError, match="SHA256 mismatch"):
            ledger.get(meta["evidence_id"], verify_integrity=True)

    def test_skip_integrity_check(self, ledger, temp_dir):
        """Test that integrity check can be skipped."""
        data = b"original data"
        meta = ledger.store(data=data, source_tool="test", extension="bin")

        # Tamper with the raw file
        raw_path = Path(temp_dir) / meta["evidence_id"] / "raw.bin"
        raw_path.write_bytes(b"tampered data")

        # Should not raise when verify_integrity=False
        retrieved = ledger.get(meta["evidence_id"], verify_integrity=False)
        assert retrieved["evidence_id"] == meta["evidence_id"]

    def test_list_evidence_empty(self, ledger):
        """Test listing evidence when empty."""
        evidence_list = ledger.list_evidence()
        assert evidence_list == []

    def test_list_evidence(self, ledger):
        """Test listing all evidence."""
        meta1 = ledger.store(data=b"data1", source_tool="tool1", extension="bin")
        meta2 = ledger.store(data=b"data2", source_tool="tool2", extension="txt")
        meta3 = ledger.store(data=b"data3", source_tool="tool3", extension="json")

        evidence_list = ledger.list_evidence()

        assert len(evidence_list) == 3
        evidence_ids = [e["evidence_id"] for e in evidence_list]
        assert meta1["evidence_id"] in evidence_ids
        assert meta2["evidence_id"] in evidence_ids
        assert meta3["evidence_id"] in evidence_ids

    def test_exists(self, ledger):
        """Test checking if evidence exists."""
        meta = ledger.store(data=b"data", source_tool="test", extension="bin")

        assert ledger.exists(meta["evidence_id"]) is True
        assert ledger.exists("nonexistent-id") is False

    def test_delete_prohibited(self, ledger):
        """Test that deletion is always prohibited."""
        meta = ledger.store(data=b"data", source_tool="test", extension="bin")

        with pytest.raises(EvidenceDeletionError, match="deletion is prohibited"):
            ledger.delete(meta["evidence_id"])

        # Evidence should still exist
        assert ledger.exists(meta["evidence_id"])

    def test_verify_all(self, ledger):
        """Test verifying all evidence integrity."""
        meta1 = ledger.store(data=b"data1", source_tool="tool1", extension="bin")
        meta2 = ledger.store(data=b"data2", source_tool="tool2", extension="bin")

        results = ledger.verify_all()

        assert len(results) == 2
        assert all(r["valid"] for r in results)

    def test_verify_all_detects_corruption(self, ledger, temp_dir):
        """Test that verify_all detects corrupted evidence."""
        meta1 = ledger.store(data=b"data1", source_tool="tool1", extension="bin")
        meta2 = ledger.store(data=b"data2", source_tool="tool2", extension="bin")

        # Corrupt one file
        raw_path = Path(temp_dir) / meta1["evidence_id"] / "raw.bin"
        raw_path.write_bytes(b"corrupted")

        results = ledger.verify_all()

        valid_count = sum(1 for r in results if r["valid"])
        invalid_count = sum(1 for r in results if not r["valid"])

        assert valid_count == 1
        assert invalid_count == 1

    def test_large_file_storage(self, ledger):
        """Test storing large files."""
        # Create 1MB of data
        large_data = b"x" * (1024 * 1024)
        meta = ledger.store(data=large_data, source_tool="test", extension="bin")

        assert meta["size_bytes"] == 1024 * 1024

        # Verify retrieval
        retrieved = ledger.get_raw_data(meta["evidence_id"])
        assert retrieved == large_data

    def test_unicode_in_string_data(self, ledger):
        """Test storing unicode string data."""
        unicode_data = "こんにちは世界 🌍"
        meta = ledger.store(data=unicode_data, source_tool="test", extension="txt")

        retrieved = ledger.get_raw_data(meta["evidence_id"])
        assert retrieved.decode("utf-8") == unicode_data
