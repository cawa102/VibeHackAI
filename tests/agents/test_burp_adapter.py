"""Tests for Burpsuite MCP adapter."""

from __future__ import annotations

import pytest

from src.mcp_adapters.burp_adapter import BurpAdapter
from src.mcp_adapters.base_adapter import MCPResult, MCPError


class TestBurpAdapter:
    """Tests for BurpAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return BurpAdapter(mock_mode=True)

    def test_supported_operations(self, adapter):
        """Test getting supported operations."""
        ops = adapter.get_supported_operations()

        assert "get_sitemap" in ops
        assert "spider" in ops
        assert "get_forms" in ops
        assert "get_endpoints" in ops
        assert "get_parameters" in ops

    def test_get_sitemap(self, adapter):
        """Test get sitemap."""
        result = adapter.get_sitemap("https://example.com")

        assert result.success is True
        assert "pages" in result.data
        assert len(result.data["pages"]) > 0

    def test_spider(self, adapter):
        """Test spider."""
        result = adapter.spider("https://example.com", max_depth=3)

        assert result.success is True
        assert "pages_crawled" in result.data
        assert "forms_found" in result.data

    def test_get_requests(self, adapter):
        """Test get requests."""
        result = adapter.get_requests("https://example.com")

        assert result.success is True
        assert "requests" in result.data
        assert len(result.data["requests"]) > 0

    def test_get_responses(self, adapter):
        """Test get responses."""
        result = adapter.get_responses("https://example.com")

        assert result.success is True
        assert "responses" in result.data
        assert len(result.data["responses"]) > 0

    def test_scan_passive(self, adapter):
        """Test passive scan."""
        result = adapter.scan_passive("https://example.com")

        assert result.success is True
        assert "issues" in result.data

    def test_get_forms(self, adapter):
        """Test get forms."""
        result = adapter.get_forms("https://example.com")

        assert result.success is True
        assert "forms" in result.data
        assert len(result.data["forms"]) > 0
        # Should have login form
        login_forms = [f for f in result.data["forms"] if f.get("is_login_form")]
        assert len(login_forms) > 0

    def test_get_endpoints(self, adapter):
        """Test get endpoints."""
        result = adapter.get_endpoints("https://example.com")

        assert result.success is True
        assert "endpoints" in result.data
        assert len(result.data["endpoints"]) > 0
        # Should have authenticated and public endpoints
        assert "authenticated_endpoints" in result.data
        assert "public_endpoints" in result.data

    def test_get_parameters(self, adapter):
        """Test get parameters."""
        result = adapter.get_parameters("https://example.com")

        assert result.success is True
        assert "parameters" in result.data
        assert len(result.data["parameters"]) > 0

    def test_get_cookies(self, adapter):
        """Test get cookies."""
        result = adapter.get_cookies("https://example.com")

        assert result.success is True
        assert "cookies" in result.data
        assert len(result.data["cookies"]) > 0

    def test_get_headers(self, adapter):
        """Test get headers."""
        result = adapter.get_headers("https://example.com")

        assert result.success is True
        assert "response_headers" in result.data
        assert "security_headers" in result.data

    def test_form_has_file_upload(self, adapter):
        """Test detection of file upload forms."""
        result = adapter.get_forms("https://example.com")

        assert result.success is True
        file_upload_forms = [f for f in result.data["forms"] if f.get("has_file_upload")]
        assert len(file_upload_forms) > 0

    def test_endpoints_have_auth_info(self, adapter):
        """Test endpoints have auth required info."""
        result = adapter.get_endpoints("https://example.com")

        assert result.success is True
        for endpoint in result.data["endpoints"]:
            assert "auth_required" in endpoint

    def test_result_to_evidence(self, adapter):
        """Test converting result to evidence format."""
        result = adapter.get_sitemap("https://example.com")

        evidence = result.to_evidence()

        assert evidence["source"] == "burp"
        assert evidence["source_type"] == "mcp_tool"
        assert "data" in evidence


class TestBurpAdapterEdgeCases:
    """Edge case tests for BurpAdapter."""

    @pytest.fixture
    def adapter(self):
        """Create adapter in mock mode."""
        return BurpAdapter(mock_mode=True)

    def test_unsupported_operation(self, adapter):
        """Test unsupported operation returns error result."""
        result = adapter.invoke("unsupported_operation", {})

        assert result.success is False
        assert "Unsupported operation" in result.error

    def test_spider_with_options(self, adapter):
        """Test spider with custom options."""
        result = adapter.spider(
            "https://example.com",
            max_depth=5,
            max_pages=50,
        )

        assert result.success is True

    def test_get_sitemap_extracts_base_url(self, adapter):
        """Test sitemap extracts base URL."""
        result = adapter.get_sitemap("https://example.com/path/to/page")

        assert result.success is True
        assert result.data["base_url"] == "https://example.com"

    def test_cookies_have_security_attributes(self, adapter):
        """Test cookies have security attributes."""
        result = adapter.get_cookies("https://example.com")

        for cookie in result.data["cookies"]:
            assert "httponly" in cookie
            assert "secure" in cookie
