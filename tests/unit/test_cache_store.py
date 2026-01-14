"""
Unit tests for CacheStore.
"""

import json
import pytest
import tempfile
import shutil
import time
from pathlib import Path

from src.storage.cache_store import CacheStore


class TestCacheStore:
    """Tests for CacheStore class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def cache_store(self, temp_dir):
        """Create a CacheStore with temporary directory."""
        return CacheStore(cache_dir=temp_dir)

    def test_set_and_get_string_query(self, cache_store):
        """Test caching with string query."""
        cache_store.set("cve", "CVE-2021-44228", {"severity": "critical"})

        result = cache_store.get("cve", "CVE-2021-44228")
        assert result == {"severity": "critical"}

    def test_set_and_get_dict_query(self, cache_store):
        """Test caching with dictionary query."""
        query = {"target": "192.168.1.1", "ports": "1-1000"}
        cache_store.set("snyk", query, {"vulnerabilities": []})

        result = cache_store.get("snyk", query)
        assert result == {"vulnerabilities": []}

    def test_get_not_found(self, cache_store):
        """Test getting nonexistent cache entry returns None."""
        result = cache_store.get("cve", "nonexistent")
        assert result is None

    def test_query_hash_consistency(self, cache_store):
        """Test that same query always produces same hash."""
        query = {"b": 2, "a": 1}  # Different order

        cache_store.set("test", query, {"data": "value"})

        # Query with different key order should find the same cache
        query_reordered = {"a": 1, "b": 2}
        result = cache_store.get("test", query_reordered)
        assert result == {"data": "value"}

    def test_ttl_expiration(self, cache_store):
        """Test that cache entries expire after TTL."""
        cache_store.set("test", "query", {"data": "value"}, ttl=1)

        # Should exist immediately
        assert cache_store.get("test", "query") is not None

        # Wait for expiration
        time.sleep(1.5)

        # Should be expired
        assert cache_store.get("test", "query") is None

    def test_no_ttl_never_expires(self, cache_store):
        """Test that cache without TTL doesn't expire."""
        cache_store.set("test", "query", {"data": "value"}, ttl=None)

        result = cache_store.get("test", "query")
        assert result == {"data": "value"}

    def test_ignore_expired(self, cache_store):
        """Test getting expired data with ignore_expired flag."""
        cache_store.set("test", "query", {"data": "value"}, ttl=1)

        time.sleep(1.5)

        # Should return None normally
        assert cache_store.get("test", "query") is None

        # Should return data with ignore_expired
        result = cache_store.get("test", "query", ignore_expired=True)
        assert result == {"data": "value"}

    def test_delete(self, cache_store):
        """Test deleting cache entry."""
        cache_store.set("test", "query", {"data": "value"})
        assert cache_store.get("test", "query") is not None

        deleted = cache_store.delete("test", "query")

        assert deleted is True
        assert cache_store.get("test", "query") is None

    def test_delete_not_found(self, cache_store):
        """Test deleting nonexistent entry returns False."""
        deleted = cache_store.delete("test", "nonexistent")
        assert deleted is False

    def test_clear_category(self, cache_store):
        """Test clearing all entries in a category."""
        cache_store.set("cve", "query1", {"data": 1})
        cache_store.set("cve", "query2", {"data": 2})
        cache_store.set("snyk", "query3", {"data": 3})

        count = cache_store.clear_category("cve")

        assert count == 2
        assert cache_store.get("cve", "query1") is None
        assert cache_store.get("cve", "query2") is None
        assert cache_store.get("snyk", "query3") is not None

    def test_clear_expired(self, cache_store):
        """Test clearing expired entries."""
        cache_store.set("test", "query1", {"data": 1}, ttl=1)
        cache_store.set("test", "query2", {"data": 2}, ttl=None)

        time.sleep(1.5)

        count = cache_store.clear_expired("test")

        assert count == 1
        assert cache_store.get("test", "query1") is None
        assert cache_store.get("test", "query2") is not None

    def test_clear_expired_all_categories(self, cache_store):
        """Test clearing expired entries across all categories."""
        cache_store.set("cve", "query1", {"data": 1}, ttl=1)
        cache_store.set("snyk", "query2", {"data": 2}, ttl=1)
        cache_store.set("git", "query3", {"data": 3}, ttl=None)

        time.sleep(1.5)

        count = cache_store.clear_expired()  # All categories

        assert count == 2
        assert cache_store.get("cve", "query1") is None
        assert cache_store.get("snyk", "query2") is None
        assert cache_store.get("git", "query3") is not None

    def test_list_entries(self, cache_store):
        """Test listing cache entries."""
        cache_store.set("cve", "CVE-2021-44228", {"data": 1})
        cache_store.set("cve", "CVE-2022-12345", {"data": 2})

        entries = cache_store.list_entries("cve")

        assert len(entries) == 2
        queries = [e["query"] for e in entries]
        assert "CVE-2021-44228" in queries
        assert "CVE-2022-12345" in queries

    def test_list_entries_includes_expiry_info(self, cache_store):
        """Test that list_entries includes expiry information."""
        cache_store.set("test", "query1", {"data": 1}, ttl=3600)
        cache_store.set("test", "query2", {"data": 2}, ttl=1)

        time.sleep(1.5)

        entries = cache_store.list_entries("test")

        expired_entries = [e for e in entries if e.get("expired")]
        non_expired_entries = [e for e in entries if not e.get("expired")]

        assert len(expired_entries) == 1
        assert len(non_expired_entries) == 1

    def test_list_entries_empty_category(self, cache_store):
        """Test listing entries for empty category."""
        entries = cache_store.list_entries("nonexistent")
        assert entries == []

    def test_get_stats(self, cache_store):
        """Test getting cache statistics."""
        cache_store.set("cve", "query1", {"data": 1})
        cache_store.set("cve", "query2", {"data": 2})
        cache_store.set("snyk", "query3", {"data": 3}, ttl=1)

        time.sleep(1.5)

        stats = cache_store.get_stats()

        assert stats["total_entries"] == 3
        assert stats["total_expired"] == 1
        assert "cve" in stats["categories"]
        assert "snyk" in stats["categories"]
        assert stats["categories"]["cve"]["entries"] == 2
        assert stats["categories"]["cve"]["expired"] == 0
        assert stats["categories"]["snyk"]["entries"] == 1
        assert stats["categories"]["snyk"]["expired"] == 1

    def test_complex_data_caching(self, cache_store):
        """Test caching complex nested data."""
        complex_data = {
            "results": [
                {"id": 1, "nested": {"deep": {"value": True}}},
                {"id": 2, "list": [1, 2, 3]},
            ],
            "metadata": {
                "total": 2,
                "timestamp": "2023-12-15T10:00:00Z",
            },
        }

        cache_store.set("test", "complex_query", complex_data)

        result = cache_store.get("test", "complex_query")
        assert result == complex_data

    def test_unicode_in_cache(self, cache_store):
        """Test caching data with unicode characters."""
        data = {"message": "脆弱性レポート", "emoji": "🔒"}
        query = {"search": "検索クエリ"}

        cache_store.set("test", query, data)

        result = cache_store.get("test", query)
        assert result == data
