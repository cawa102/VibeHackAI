"""
Burp Suite Passer - Normalizes Burp Suite output into common schema objects.

Handles sitemap, request/response pairs, and scan results.
"""

from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from .base import BasePasser, MCPType, PasserRegistry, PasserResult
from ..schemas import Observation
from ..schemas.evidence import EvidenceItem


@PasserRegistry.register
class BurpPasser(BasePasser):
    """
    Passer for Burp Suite output.

    Handles XML exports, sitemap data, and request/response pairs.
    """

    mcp_type = MCPType.BURP
    tool_name = "burp"

    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """Check if this is Burp Suite output."""
        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, str):
            # Check for Burp XML format
            if "<?xml" in raw_output and ("burpVersion" in raw_output or "<items" in raw_output):
                return True
            # Try JSON
            try:
                data = json.loads(raw_output)
                return self._is_burp_json(data)
            except json.JSONDecodeError:
                return False

        if isinstance(raw_output, dict):
            return self._is_burp_json(raw_output)

        return False

    def _is_burp_json(self, data: Dict[str, Any]) -> bool:
        """Check if JSON data is from Burp."""
        burp_indicators = ["request", "response", "sitemap", "issues", "host", "method", "path"]
        return any(key in data for key in burp_indicators)

    def normalize(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize Burp Suite output.

        Args:
            raw_output: Burp XML or JSON output.
            **kwargs: Additional parameters.

        Returns:
            PasserResult with Observation and EvidenceItem objects.
        """
        result = self._create_result()

        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, dict):
            return self._normalize_json(raw_output, result)

        if isinstance(raw_output, str):
            # Try XML first
            if "<?xml" in raw_output:
                try:
                    root = ET.fromstring(raw_output)
                    return self._normalize_xml(root, result)
                except ET.ParseError:
                    pass

            # Try JSON
            try:
                data = json.loads(raw_output)
                return self._normalize_json(data, result)
            except json.JSONDecodeError:
                result.add_error("Failed to parse Burp output as XML or JSON")
                return result

        result.add_error("Unsupported Burp output format")
        return result

    def _normalize_xml(
        self,
        root: ET.Element,
        result: PasserResult,
    ) -> PasserResult:
        """Normalize Burp XML export."""
        # Handle sitemap items
        for item in root.findall(".//item"):
            obs = self._parse_xml_item(item, result)
            if obs:
                result.observations.append(obs)

        # Create summary observation
        if result.observations:
            summary_obs = self._create_summary_observation(
                f"{len(result.observations)} HTTP exchanges captured",
                result,
            )
            if summary_obs:
                result.observations.insert(0, summary_obs)

        return result

    def _parse_xml_item(
        self,
        item: ET.Element,
        result: PasserResult,
    ) -> Optional[Observation]:
        """Parse a single item from Burp XML."""
        try:
            url = self._get_element_text(item, "url", "")
            host = self._get_element_text(item, "host", "")
            port = self._get_element_text(item, "port", "80")
            protocol = self._get_element_text(item, "protocol", "http")
            method = self._get_element_text(item, "method", "GET")
            path = self._get_element_text(item, "path", "/")
            status = self._get_element_text(item, "status", "")
            response_length = self._get_element_text(item, "responselength", "0")
            mime_type = self._get_element_text(item, "mimetype", "")

            # Get request/response (may be base64 encoded)
            request_elem = item.find("request")
            response_elem = item.find("response")

            request_data = self._decode_burp_data(request_elem)
            response_data = self._decode_burp_data(response_elem)

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="http_exchange",
                summary=f"{method} {path} -> {status}",
                raw_output_preview=request_data[:500] if request_data else "",
                success=True,
                metadata={
                    "url": url,
                    "host": host,
                    "port": self._safe_int(port),
                    "protocol": protocol,
                    "method": method,
                    "path": path,
                    "status_code": self._safe_int(status),
                    "response_length": self._safe_int(response_length),
                    "mime_type": mime_type,
                    "has_request": bool(request_data),
                    "has_response": bool(response_data),
                },
            )
            return observation
        except Exception as e:
            result.add_warning(f"Failed to parse Burp XML item: {e}")
            return None

    def _get_element_text(
        self,
        parent: ET.Element,
        tag: str,
        default: str = "",
    ) -> str:
        """Get text from child element."""
        elem = parent.find(tag)
        return elem.text if elem is not None and elem.text else default

    def _decode_burp_data(self, elem: Optional[ET.Element]) -> str:
        """Decode Burp request/response data."""
        if elem is None or not elem.text:
            return ""

        is_base64 = elem.get("base64", "false").lower() == "true"

        if is_base64:
            try:
                return base64.b64decode(elem.text).decode("utf-8", errors="ignore")
            except Exception:
                return elem.text
        return elem.text

    def _normalize_json(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize Burp JSON output."""
        result.raw_data = data

        # Handle sitemap
        if "sitemap" in data:
            for entry in data["sitemap"]:
                obs = self._parse_json_entry(entry, result)
                if obs:
                    result.observations.append(obs)

        # Handle single request/response pair
        elif "request" in data or "response" in data:
            obs = self._parse_json_entry(data, result)
            if obs:
                result.observations.append(obs)

        # Handle issues (scanner results)
        if "issues" in data:
            for issue in data["issues"]:
                obs = self._parse_issue(issue, result)
                if obs:
                    result.observations.append(obs)

        # Create summary
        if result.observations:
            summary_obs = self._create_summary_observation(
                f"{len(result.observations)} items processed",
                result,
            )
            if summary_obs:
                result.observations.insert(0, summary_obs)

        return result

    def _parse_json_entry(
        self,
        entry: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[Observation]:
        """Parse a JSON entry into Observation."""
        try:
            url = entry.get("url", "")
            method = entry.get("method", "GET")
            status = entry.get("status") or entry.get("statusCode") or entry.get("response", {}).get("status")
            path = entry.get("path", "/")

            if url and not path:
                parsed = urlparse(url)
                path = parsed.path or "/"

            host = entry.get("host", "")
            if url and not host:
                parsed = urlparse(url)
                host = parsed.netloc

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="http_exchange",
                summary=f"{method} {path}" + (f" -> {status}" if status else ""),
                success=True,
                metadata={
                    "url": url,
                    "host": host,
                    "method": method,
                    "path": path,
                    "status_code": self._safe_int(status) if status else None,
                    "request_headers": entry.get("request", {}).get("headers"),
                    "response_headers": entry.get("response", {}).get("headers"),
                },
            )
            return observation
        except Exception as e:
            result.add_warning(f"Failed to parse Burp JSON entry: {e}")
            return None

    def _parse_issue(
        self,
        issue: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[Observation]:
        """Parse a Burp issue/finding."""
        try:
            name = issue.get("name") or issue.get("issueName") or "Unknown Issue"
            severity = issue.get("severity", "information")
            confidence = issue.get("confidence", "tentative")
            url = issue.get("url") or issue.get("path", "")

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="issue_detected",
                summary=f"[{severity.upper()}] {name}",
                success=True,
                metadata={
                    "issue_name": name,
                    "severity": severity,
                    "confidence": confidence,
                    "url": url,
                    "issue_detail": issue.get("issueDetail") or issue.get("detail"),
                    "remediation": issue.get("remediationDetail") or issue.get("remediation"),
                    "issue_type": issue.get("issueType") or issue.get("type"),
                },
            )
            return observation
        except Exception as e:
            result.add_warning(f"Failed to parse Burp issue: {e}")
            return None

    def _create_summary_observation(
        self,
        summary: str,
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create a summary observation."""
        try:
            return Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="summary",
                summary=f"Burp Suite: {summary}",
                success=True,
                metadata={
                    "total_observations": len(result.observations),
                },
            )
        except Exception as e:
            result.add_warning(f"Failed to create summary observation: {e}")
            return None
