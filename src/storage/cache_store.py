"""
Cache Store for PentestAgent.

Provides caching for MCP query results with TTL support and query hashing.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Union


class CacheStore:
    """
    Cache store for MCP query results.

    Supports:
    - Query-based caching with hash keys
    - TTL (time-to-live) expiration
    - Multiple cache categories (cve, snyk, git, etc.)
    """

    # Default TTL in seconds (1 hour)
    DEFAULT_TTL = 3600

    def __init__(self, cache_dir: Union[str, Path]):
        """
        Initialize CacheStore.

        Args:
            cache_dir: Directory to store cache files.
        """
        self.cache_dir = Path(cache_dir).resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _compute_query_hash(self, query: Union[str, dict]) -> str:
        """
        Compute a hash for a query.

        Args:
            query: Query string or dictionary.

        Returns:
            SHA256 hash of the query (first 16 characters).
        """
        if isinstance(query, dict):
            # Sort keys for consistent hashing
            query_str = json.dumps(query, sort_keys=True, ensure_ascii=False)
        else:
            query_str = str(query)

        full_hash = hashlib.sha256(query_str.encode("utf-8")).hexdigest()
        return full_hash[:16]

    def _get_cache_path(self, category: str, query_hash: str) -> Path:
        """Get the path to a cache file."""
        category_dir = self.cache_dir / category
        category_dir.mkdir(parents=True, exist_ok=True)
        return category_dir / f"{query_hash}.json"

    def _is_expired(self, cached_data: dict) -> bool:
        """Check if cached data has expired."""
        if "expires_at" not in cached_data:
            return False

        expires_at = cached_data["expires_at"]
        if expires_at is None:
            return False

        return time.time() > expires_at

    def get(
        self,
        category: str,
        query: Union[str, dict],
        ignore_expired: bool = False
    ) -> Optional[Any]:
        """
        Get cached data for a query.

        Args:
            category: Cache category (e.g., "cve", "snyk", "git").
            query: Query string or dictionary.
            ignore_expired: If True, return expired data anyway.

        Returns:
            Cached data or None if not found/expired.
        """
        query_hash = self._compute_query_hash(query)
        cache_path = self._get_cache_path(category, query_hash)

        if not cache_path.exists():
            return None

        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

        if not ignore_expired and self._is_expired(cached):
            return None

        return cached.get("data")

    def set(
        self,
        category: str,
        query: Union[str, dict],
        data: Any,
        ttl: Optional[int] = None
    ) -> str:
        """
        Store data in cache.

        Args:
            category: Cache category.
            query: Query string or dictionary.
            data: Data to cache.
            ttl: Time-to-live in seconds. None for no expiration.
                 Use DEFAULT_TTL constant for default.

        Returns:
            Cache key (query hash).
        """
        query_hash = self._compute_query_hash(query)
        cache_path = self._get_cache_path(category, query_hash)

        cached_at = time.time()
        expires_at = None if ttl is None else cached_at + ttl

        cache_entry = {
            "query": query,
            "query_hash": query_hash,
            "data": data,
            "cached_at": cached_at,
            "cached_at_iso": datetime.utcfromtimestamp(cached_at).isoformat() + "Z",
            "expires_at": expires_at,
            "ttl": ttl,
        }

        cache_path.write_text(
            json.dumps(cache_entry, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )

        return query_hash

    def delete(self, category: str, query: Union[str, dict]) -> bool:
        """
        Delete a cache entry.

        Args:
            category: Cache category.
            query: Query string or dictionary.

        Returns:
            True if entry was deleted, False if not found.
        """
        query_hash = self._compute_query_hash(query)
        cache_path = self._get_cache_path(category, query_hash)

        if cache_path.exists():
            cache_path.unlink()
            return True

        return False

    def clear_category(self, category: str) -> int:
        """
        Clear all cache entries in a category.

        Args:
            category: Cache category to clear.

        Returns:
            Number of entries deleted.
        """
        category_dir = self.cache_dir / category

        if not category_dir.exists():
            return 0

        count = 0
        for cache_file in category_dir.iterdir():
            if cache_file.suffix == ".json":
                cache_file.unlink()
                count += 1

        return count

    def clear_expired(self, category: Optional[str] = None) -> int:
        """
        Clear expired cache entries.

        Args:
            category: Optional category to limit clearing.
                      If None, clears all categories.

        Returns:
            Number of entries deleted.
        """
        count = 0

        if category:
            categories = [category]
        else:
            categories = [
                d.name for d in self.cache_dir.iterdir()
                if d.is_dir()
            ]

        for cat in categories:
            category_dir = self.cache_dir / cat
            if not category_dir.exists():
                continue

            for cache_file in category_dir.iterdir():
                if cache_file.suffix != ".json":
                    continue

                try:
                    cached = json.loads(cache_file.read_text(encoding="utf-8"))
                    if self._is_expired(cached):
                        cache_file.unlink()
                        count += 1
                except (json.JSONDecodeError, KeyError):
                    continue

        return count

    def list_entries(self, category: str) -> list[dict]:
        """
        List all cache entries in a category.

        Args:
            category: Cache category.

        Returns:
            List of cache entry metadata (without full data).
        """
        category_dir = self.cache_dir / category

        if not category_dir.exists():
            return []

        entries = []
        for cache_file in category_dir.iterdir():
            if cache_file.suffix != ".json":
                continue

            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                entries.append({
                    "query_hash": cached.get("query_hash"),
                    "query": cached.get("query"),
                    "cached_at_iso": cached.get("cached_at_iso"),
                    "expires_at": cached.get("expires_at"),
                    "expired": self._is_expired(cached),
                })
            except (json.JSONDecodeError, KeyError):
                continue

        # Sort by cache time, newest first
        entries.sort(key=lambda x: x.get("cached_at_iso", ""), reverse=True)
        return entries

    def get_stats(self) -> dict:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics per category.
        """
        stats = {
            "total_entries": 0,
            "total_expired": 0,
            "categories": {},
        }

        for category_dir in self.cache_dir.iterdir():
            if not category_dir.is_dir():
                continue

            category = category_dir.name
            cat_stats = {"entries": 0, "expired": 0}

            for cache_file in category_dir.iterdir():
                if cache_file.suffix != ".json":
                    continue

                cat_stats["entries"] += 1

                try:
                    cached = json.loads(cache_file.read_text(encoding="utf-8"))
                    if self._is_expired(cached):
                        cat_stats["expired"] += 1
                except (json.JSONDecodeError, KeyError):
                    continue

            stats["categories"][category] = cat_stats
            stats["total_entries"] += cat_stats["entries"]
            stats["total_expired"] += cat_stats["expired"]

        return stats
