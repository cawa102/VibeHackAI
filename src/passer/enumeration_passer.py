"""
Enumeration Passer - Normalizes hexstrike-ai enumeration tool outputs.

Handles outputs from: burpsuite, nikto, dirb, gobuster, ffuf, feroxbuster,
dirsearch, enum4linux, smbmap
"""

from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .base import (
    BasePasser,
    HexstrikeToolCategory,
    HexstrikeTool,
    PasserRegistry,
    PasserResult,
)
from ..schemas import Observation, VulnCandidate
from ..schemas.evidence import EvidenceItem


@PasserRegistry.register
class EnumerationPasser(BasePasser):
    """
    Passer for hexstrike-ai enumeration tools.

    Normalizes outputs from web scanners, directory busters, and SMB tools.
    """

    category = HexstrikeToolCategory.ENUMERATION
    supported_tools = [
        HexstrikeTool.BURPSUITE,
        HexstrikeTool.NIKTO,
        HexstrikeTool.DIRB,
        HexstrikeTool.GOBUSTER,
        HexstrikeTool.FFUF,
        HexstrikeTool.FEROXBUSTER,
        HexstrikeTool.DIRSEARCH,
        HexstrikeTool.ENUM4LINUX,
        HexstrikeTool.SMBMAP,
    ]

    def normalize(
        self,
        raw_output: Dict[str, Any],
        tool: HexstrikeTool,
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize enumeration tool output.

        Args:
            raw_output: Raw output from hexstrike-ai.
            tool: The specific tool that generated the output.
            **kwargs: Additional parameters.

        Returns:
            PasserResult with Observation and VulnCandidate objects.
        """
        result = self._create_result(tool)
        data = self._extract_result(raw_output)

        if tool == HexstrikeTool.BURPSUITE:
            return self._normalize_burp(data, result)
        elif tool == HexstrikeTool.NIKTO:
            return self._normalize_nikto(data, result)
        elif tool in (HexstrikeTool.DIRB, HexstrikeTool.GOBUSTER,
                      HexstrikeTool.FFUF, HexstrikeTool.FEROXBUSTER,
                      HexstrikeTool.DIRSEARCH):
            return self._normalize_dirbuster(data, tool, result)
        elif tool == HexstrikeTool.ENUM4LINUX:
            return self._normalize_enum4linux(data, result)
        elif tool == HexstrikeTool.SMBMAP:
            return self._normalize_smbmap(data, result)
        else:
            result.add_warning(f"Unhandled enumeration tool: {tool}")
            result.raw_data = raw_output
            return result

    def _normalize_burp(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize Burp Suite output."""
        result.raw_data = data

        # Check for XML output embedded in result
        raw_xml = data.get("xml") or data.get("raw_output")
        if raw_xml and isinstance(raw_xml, str) and "<?xml" in raw_xml:
            return self._parse_burp_xml(raw_xml, result)

        # Handle sitemap
        if "sitemap" in data:
            for entry in data["sitemap"]:
                obs = self._parse_http_entry(entry, "burp", result)
                if obs:
                    result.observations.append(obs)

        # Handle single request/response
        elif "request" in data or "response" in data:
            obs = self._parse_http_entry(data, "burp", result)
            if obs:
                result.observations.append(obs)

        # Handle issues (scanner findings)
        if "issues" in data:
            for issue in data["issues"]:
                obs, vuln = self._parse_burp_issue(issue, result)
                if obs:
                    result.observations.append(obs)
                if vuln:
                    result.vuln_candidates.append(vuln)

        # Summary
        if result.observations:
            summary_obs = self._create_summary("burp", result)
            if summary_obs:
                result.observations.insert(0, summary_obs)

        return result

    def _parse_burp_xml(
        self,
        xml_data: str,
        result: PasserResult,
    ) -> PasserResult:
        """Parse Burp XML export."""
        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError as e:
            result.add_error(f"Failed to parse Burp XML: {e}")
            return result

        for item in root.findall(".//item"):
            obs = self._parse_burp_xml_item(item, result)
            if obs:
                result.observations.append(obs)

        if result.observations:
            summary_obs = self._create_summary("burp", result)
            if summary_obs:
                result.observations.insert(0, summary_obs)

        return result

    def _parse_burp_xml_item(
        self,
        item: ET.Element,
        result: PasserResult,
    ) -> Optional[Observation]:
        """Parse a Burp XML item element."""
        try:
            url = self._get_xml_text(item, "url", "")
            host = self._get_xml_text(item, "host", "")
            port = self._get_xml_text(item, "port", "80")
            method = self._get_xml_text(item, "method", "GET")
            path = self._get_xml_text(item, "path", "/")
            status = self._get_xml_text(item, "status", "")

            # Decode request/response
            request_elem = item.find("request")
            request_data = self._decode_burp_data(request_elem)

            return Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool="burp",
                action="http_exchange",
                summary=f"{method} {path} -> {status}",
                raw_output_preview=request_data[:500] if request_data else "",
                success=True,
                metadata={
                    "url": url,
                    "host": host,
                    "port": self._safe_int(port),
                    "method": method,
                    "path": path,
                    "status_code": self._safe_int(status),
                },
            )
        except Exception as e:
            result.add_warning(f"Failed to parse Burp XML item: {e}")
            return None

    def _decode_burp_data(self, elem: Optional[ET.Element]) -> str:
        """Decode base64 Burp data."""
        if elem is None or not elem.text:
            return ""

        is_base64 = elem.get("base64", "false").lower() == "true"
        if is_base64:
            try:
                return base64.b64decode(elem.text).decode("utf-8", errors="ignore")
            except Exception:
                return elem.text
        return elem.text

    def _get_xml_text(
        self,
        parent: ET.Element,
        tag: str,
        default: str = "",
    ) -> str:
        """Get text from child element."""
        elem = parent.find(tag)
        return elem.text if elem is not None and elem.text else default

    def _parse_burp_issue(
        self,
        issue: Dict[str, Any],
        result: PasserResult,
    ) -> tuple[Optional[Observation], Optional[VulnCandidate]]:
        """Parse a Burp issue/finding."""
        try:
            name = issue.get("name") or issue.get("issueName") or "Unknown Issue"
            severity = issue.get("severity", "information").lower()
            confidence = issue.get("confidence", "tentative")
            url = issue.get("url") or issue.get("path", "")

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool="burp",
                action="issue_detected",
                summary=f"[{severity.upper()}] {name}",
                success=True,
                metadata={
                    "issue_name": name,
                    "severity": severity,
                    "confidence": confidence,
                    "url": url,
                    "detail": issue.get("issueDetail") or issue.get("detail"),
                },
            )

            # Create VulnCandidate for significant findings
            vuln_candidate = None
            if severity in ("high", "medium", "critical"):
                vuln_candidate = VulnCandidate(
                    session_id=self.session_id,
                    scope_tag=self.scope_tag,
                    created_by=self.created_by,
                    title=name,
                    severity=severity,
                    source_tool="burp",
                    description=issue.get("issueDetail") or issue.get("detail", ""),
                    affected_component=url,
                    confidence_score=0.8 if confidence == "certain" else 0.5,
                )

            return observation, vuln_candidate
        except Exception as e:
            result.add_warning(f"Failed to parse Burp issue: {e}")
            return None, None

    def _normalize_nikto(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize Nikto output."""
        result.raw_data = data

        target = data.get("target") or data.get("host", "unknown")
        findings = data.get("findings", data.get("vulnerabilities", []))

        for finding in findings:
            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool="nikto",
                action="finding",
                summary=finding.get("message") or finding.get("description", "Nikto finding"),
                success=True,
                metadata={
                    "osvdb_id": finding.get("osvdb") or finding.get("id"),
                    "uri": finding.get("uri") or finding.get("path"),
                    "method": finding.get("method", "GET"),
                    "target": target,
                },
            )
            result.observations.append(observation)

            # Create VulnCandidate if indicated
            if finding.get("severity") or finding.get("osvdb"):
                vuln = VulnCandidate(
                    session_id=self.session_id,
                    scope_tag=self.scope_tag,
                    created_by=self.created_by,
                    title=f"Nikto: {finding.get('message', 'Finding')[:50]}",
                    severity=finding.get("severity", "info"),
                    source_tool="nikto",
                    description=finding.get("message", ""),
                    affected_component=f"{target}{finding.get('uri', '')}",
                    references=[f"OSVDB-{finding['osvdb']}"] if finding.get("osvdb") else [],
                )
                result.vuln_candidates.append(vuln)

        summary_obs = self._create_summary("nikto", result)
        if summary_obs:
            result.observations.insert(0, summary_obs)

        return result

    def _normalize_dirbuster(
        self,
        data: Dict[str, Any],
        tool: HexstrikeTool,
        result: PasserResult,
    ) -> PasserResult:
        """Normalize directory busting tool output."""
        result.raw_data = data

        tool_name = tool.value.replace("_scan", "")

        # Common format: list of discovered paths
        discoveries = (
            data.get("results", []) or
            data.get("paths", []) or
            data.get("directories", []) or
            data.get("files", [])
        )

        target = data.get("target") or data.get("url", "")

        for item in discoveries:
            if isinstance(item, str):
                path = item
                status = 200
                size = 0
            else:
                path = item.get("path") or item.get("url", "")
                status = self._safe_int(item.get("status") or item.get("status_code"), result=result)
                size = self._safe_int(item.get("size") or item.get("length"), result=result)

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=tool_name,
                action="directory_discovery",
                summary=f"[{status}] {path}",
                success=True,
                metadata={
                    "path": path,
                    "status_code": status,
                    "size": size,
                    "target": target,
                },
            )
            result.observations.append(observation)

        summary_obs = self._create_summary(tool_name, result)
        if summary_obs:
            result.observations.insert(0, summary_obs)

        return result

    def _normalize_enum4linux(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize enum4linux output."""
        result.raw_data = data

        target = data.get("target", "unknown")

        # Users
        users = data.get("users", [])
        if users:
            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool="enum4linux",
                action="user_enumeration",
                summary=f"Found {len(users)} users",
                success=True,
                metadata={"users": users, "target": target},
            )
            result.observations.append(observation)

        # Shares
        shares = data.get("shares", [])
        if shares:
            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool="enum4linux",
                action="share_enumeration",
                summary=f"Found {len(shares)} shares",
                success=True,
                metadata={"shares": shares, "target": target},
            )
            result.observations.append(observation)

        # Groups
        groups = data.get("groups", [])
        if groups:
            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool="enum4linux",
                action="group_enumeration",
                summary=f"Found {len(groups)} groups",
                success=True,
                metadata={"groups": groups, "target": target},
            )
            result.observations.append(observation)

        # Domain info
        domain_info = data.get("domain", {})
        if domain_info:
            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool="enum4linux",
                action="domain_info",
                summary=f"Domain: {domain_info.get('name', 'unknown')}",
                success=True,
                metadata={"domain": domain_info, "target": target},
            )
            result.observations.append(observation)

        # Create vuln candidates for null session, etc.
        if data.get("null_session"):
            vuln = VulnCandidate(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                title="SMB Null Session Allowed",
                severity="medium",
                source_tool="enum4linux",
                description="Target allows null session enumeration",
                affected_component=target,
            )
            result.vuln_candidates.append(vuln)

        summary_obs = self._create_summary("enum4linux", result)
        if summary_obs:
            result.observations.insert(0, summary_obs)

        return result

    def _normalize_smbmap(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize smbmap output."""
        result.raw_data = data

        target = data.get("target") or data.get("host", "unknown")
        shares = data.get("shares", [])

        for share in shares:
            share_name = share.get("name") or share.get("share", "unknown")
            permissions = share.get("permissions") or share.get("access", "")

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool="smbmap",
                action="share_access",
                summary=f"Share: {share_name} [{permissions}]",
                success=True,
                metadata={
                    "share_name": share_name,
                    "permissions": permissions,
                    "target": target,
                    "contents": share.get("contents", []),
                },
            )
            result.observations.append(observation)

            # Check for writable shares
            if "WRITE" in str(permissions).upper():
                vuln = VulnCandidate(
                    session_id=self.session_id,
                    scope_tag=self.scope_tag,
                    created_by=self.created_by,
                    title=f"Writable SMB Share: {share_name}",
                    severity="high",
                    source_tool="smbmap",
                    description=f"Share {share_name} has write permissions",
                    affected_component=f"{target}\\{share_name}",
                )
                result.vuln_candidates.append(vuln)

        summary_obs = self._create_summary("smbmap", result)
        if summary_obs:
            result.observations.insert(0, summary_obs)

        return result

    def _parse_http_entry(
        self,
        entry: Dict[str, Any],
        tool_name: str,
        result: PasserResult,
    ) -> Optional[Observation]:
        """Parse HTTP request/response entry."""
        try:
            url = entry.get("url", "")
            method = entry.get("method", "GET")
            status = entry.get("status") or entry.get("statusCode")
            path = entry.get("path", "/")

            if url and not path:
                parsed = urlparse(url)
                path = parsed.path or "/"

            return Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=tool_name,
                action="http_exchange",
                summary=f"{method} {path}" + (f" -> {status}" if status else ""),
                success=True,
                metadata={
                    "url": url,
                    "method": method,
                    "path": path,
                    "status_code": self._safe_int(status) if status else None,
                },
            )
        except Exception as e:
            result.add_warning(f"Failed to parse HTTP entry: {e}")
            return None

    def _create_summary(
        self,
        tool_name: str,
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create summary observation."""
        try:
            obs_count = len(result.observations)
            vuln_count = len(result.vuln_candidates)

            summary_parts = [f"{obs_count} observations"]
            if vuln_count > 0:
                summary_parts.append(f"{vuln_count} vulnerabilities")

            return Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=tool_name,
                action="summary",
                summary=f"{tool_name}: " + ", ".join(summary_parts),
                success=True,
                metadata={
                    "observation_count": obs_count,
                    "vuln_candidate_count": vuln_count,
                },
            )
        except Exception as e:
            result.add_warning(f"Failed to create summary: {e}")
            return None
