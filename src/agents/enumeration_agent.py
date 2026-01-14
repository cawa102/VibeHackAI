"""
Enumeration Agent for PentestAgent.

Performs application-layer enumeration to discover input points,
authentication mechanisms, and attack surface.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from .base_agent import (
    BaseAgent,
    AgentConfig,
    AgentContext,
    AgentOutput,
    AgentType,
)
from ..mcp_adapters.burp_adapter import BurpAdapter
from ..mcp_adapters.nmap_adapter import NmapAdapter
from ..mcp_adapters.base_adapter import MCPResult
from ..patch.patch import Patch, PatchOperation
from ..patch.operations import OperationType


class EnumerationAgent(BaseAgent):
    """
    Enumeration Agent.

    Responsibilities:
    - Web application site map collection via Burpsuite
    - Input point detection (forms, APIs, parameters)
    - Authentication/authorization boundary identification
    - File upload detection
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        burp_adapter: Optional[BurpAdapter] = None,
        nmap_adapter: Optional[NmapAdapter] = None,
        mock_mode: bool = False,
    ):
        """
        Initialize Enumeration Agent.

        Args:
            config: Agent configuration.
            burp_adapter: Burpsuite MCP adapter.
            nmap_adapter: Nmap MCP adapter (for service details).
            mock_mode: If True, use mock adapters.
        """
        if config is None:
            config = AgentConfig(
                agent_type=AgentType.ENUMERATION,
                timeout_seconds=900,  # 15 minutes
            )

        super().__init__(config)

        # Initialize adapters
        self.burp = burp_adapter or BurpAdapter(mock_mode=mock_mode)
        self.nmap = nmap_adapter or NmapAdapter(mock_mode=mock_mode)

        # Results storage
        self._evidences: List[Dict[str, Any]] = []
        self._observations: List[Dict[str, Any]] = []
        self._input_points: List[Dict[str, Any]] = []
        self._auth_info: Dict[str, Any] = {}
        self._endpoints: List[Dict[str, Any]] = []

    def _execute(self, context: AgentContext) -> AgentOutput:
        """
        Execute enumeration.

        Args:
            context: Agent context.

        Returns:
            AgentOutput with results.
        """
        self._evidences = []
        self._observations = []
        self._input_points = []
        self._auth_info = {}
        self._endpoints = []

        # Extract web services from target profile
        web_targets = self._extract_web_targets(context)
        if not web_targets:
            return self._create_error_output(
                context, "No web targets found in target profile"
            )

        self._record_decision(
            "target_selection",
            f"Processing {len(web_targets)} web targets",
            f"Extracted {len(web_targets)} web services from target profile",
            inputs={"target_profile": context.target_profile},
            outputs={"web_targets": web_targets},
        )

        # Process each web target
        targets_processed = 0
        for target_url in web_targets:
            try:
                self._process_web_target(target_url)
                targets_processed += 1
            except Exception as e:
                self._add_warning(f"Failed to process {target_url}: {str(e)}")

        # Analyze collected data
        self._analyze_input_points()
        self._analyze_authentication()

        # Generate patch
        operations = self._generate_operations()
        patch = self._create_patch(context, operations)

        # Create phase result
        phase_result = {
            "targets_processed": targets_processed,
            "input_points_found": len(self._input_points),
            "endpoints_found": len(self._endpoints),
            "forms_found": sum(1 for ip in self._input_points if ip.get("type") == "form"),
            "api_endpoints_found": sum(1 for ip in self._input_points if ip.get("type") == "api"),
            "file_uploads_found": sum(1 for ip in self._input_points if ip.get("has_file_upload")),
            "login_forms_found": sum(1 for ip in self._input_points if ip.get("is_login_form")),
            "auth_mechanisms_detected": list(self._auth_info.get("mechanisms", [])),
        }

        return self._create_success_output(context, patch, phase_result)

    def _extract_web_targets(self, context: AgentContext) -> List[str]:
        """
        Extract web targets from target profile.

        Args:
            context: Agent context.

        Returns:
            List of web service URLs.
        """
        web_targets = []

        # Check target profile for web services
        target_profile = context.target_profile or {}

        # Look for URLs in scope
        scope = context.scope or {}
        for target in scope.get("targets", []):
            if target.get("type") == "url":
                web_targets.append(target.get("value"))
            elif target.get("type") == "domain":
                # Add common web ports
                domain = target.get("value")
                web_targets.append(f"https://{domain}")
                web_targets.append(f"http://{domain}")

        # Look for web services in target profile
        for target_id, profile in target_profile.get("targets", {}).items():
            ports = profile.get("ports", [])
            hostnames = profile.get("hostnames", [])
            ip = profile.get("ip", target_id)

            for port in ports:
                if port in [80, 8080, 8000, 3000]:
                    host = hostnames[0] if hostnames else ip
                    web_targets.append(f"http://{host}:{port}" if port != 80 else f"http://{host}")
                elif port in [443, 8443]:
                    host = hostnames[0] if hostnames else ip
                    web_targets.append(f"https://{host}:{port}" if port != 443 else f"https://{host}")

        # Deduplicate
        return list(set(web_targets))

    def _process_web_target(self, target_url: str) -> None:
        """
        Process a web target.

        Args:
            target_url: URL to process.
        """
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            self._add_warning(f"Invalid URL format: {target_url}")
            return

        # Spider the target
        spider_result = self.burp.spider(target_url, max_depth=3)
        if spider_result.success:
            self._add_evidence(spider_result)
            self._add_observation(
                "spider_complete",
                f"Spidered {target_url}",
                spider_result.data,
            )

        # Get sitemap
        sitemap_result = self.burp.get_sitemap(target_url)
        if sitemap_result.success:
            self._add_evidence(sitemap_result)
            self._extract_sitemap_data(target_url, sitemap_result.data)

        # Get forms
        forms_result = self.burp.get_forms(target_url)
        if forms_result.success:
            self._add_evidence(forms_result)
            self._extract_forms(target_url, forms_result.data)

        # Get API endpoints
        endpoints_result = self.burp.get_endpoints(target_url)
        if endpoints_result.success:
            self._add_evidence(endpoints_result)
            self._extract_endpoints(target_url, endpoints_result.data)

        # Get parameters
        params_result = self.burp.get_parameters(target_url)
        if params_result.success:
            self._add_evidence(params_result)
            self._extract_parameters(target_url, params_result.data)

        # Get cookies
        cookies_result = self.burp.get_cookies(target_url)
        if cookies_result.success:
            self._add_evidence(cookies_result)
            self._extract_cookies(target_url, cookies_result.data)

        # Get headers
        headers_result = self.burp.get_headers(target_url)
        if headers_result.success:
            self._add_evidence(headers_result)
            self._extract_headers(target_url, headers_result.data)

        # Run passive scan
        passive_result = self.burp.scan_passive(target_url)
        if passive_result.success:
            self._add_evidence(passive_result)
            self._extract_passive_issues(target_url, passive_result.data)

    def _extract_sitemap_data(
        self,
        target_url: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract sitemap data."""
        if not data:
            return

        pages = data.get("pages", [])
        self._add_observation(
            "sitemap",
            f"Discovered {len(pages)} pages on {target_url}",
            {
                "target": target_url,
                "pages": pages,
                "total_pages": data.get("total_pages", len(pages)),
                "crawl_depth": data.get("crawl_depth"),
            },
        )

    def _extract_forms(
        self,
        target_url: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract form data."""
        if not data:
            return

        forms = data.get("forms", [])
        for form in forms:
            input_point = {
                "id": f"input-{uuid.uuid4().hex[:8]}",
                "type": "form",
                "target_url": target_url,
                "url": form.get("url"),
                "method": form.get("method", "POST"),
                "action": form.get("action"),
                "enctype": form.get("enctype"),
                "fields": form.get("fields", []),
                "is_login_form": form.get("is_login_form", False),
                "has_file_upload": form.get("has_file_upload", False),
            }
            self._input_points.append(input_point)

            # Record observation
            form_type = "login form" if form.get("is_login_form") else "form"
            self._add_observation(
                "form_discovered",
                f"Found {form_type} at {form.get('url')}",
                input_point,
            )

    def _extract_endpoints(
        self,
        target_url: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract API endpoint data."""
        if not data:
            return

        endpoints = data.get("endpoints", [])
        for endpoint in endpoints:
            endpoint_info = {
                "id": f"endpoint-{uuid.uuid4().hex[:8]}",
                "type": "api",
                "target_url": target_url,
                "path": endpoint.get("path"),
                "methods": endpoint.get("methods", []),
                "content_type": endpoint.get("content_type"),
                "auth_required": endpoint.get("auth_required", False),
                "parameters": endpoint.get("parameters", []),
            }
            self._endpoints.append(endpoint_info)

            # Also add as input point
            for method in endpoint.get("methods", []):
                input_point = {
                    "id": f"input-{uuid.uuid4().hex[:8]}",
                    "type": "api",
                    "target_url": target_url,
                    "url": f"{target_url.rstrip('/')}{endpoint.get('path')}",
                    "method": method,
                    "content_type": endpoint.get("content_type"),
                    "auth_required": endpoint.get("auth_required", False),
                    "parameters": endpoint.get("parameters", []),
                    "has_file_upload": any(
                        p.get("type") == "file"
                        for p in endpoint.get("parameters", [])
                    ),
                }
                self._input_points.append(input_point)

        self._add_observation(
            "endpoints_discovered",
            f"Found {len(endpoints)} API endpoints on {target_url}",
            {
                "target": target_url,
                "endpoints": endpoints,
                "authenticated_count": data.get("authenticated_endpoints", 0),
                "public_count": data.get("public_endpoints", 0),
            },
        )

    def _extract_parameters(
        self,
        target_url: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract parameter data."""
        if not data:
            return

        params = data.get("parameters", [])
        self._add_observation(
            "parameters_discovered",
            f"Found {len(params)} unique parameters on {target_url}",
            {
                "target": target_url,
                "parameters": params,
                "file_parameters": data.get("file_parameters", 0),
                "auth_parameters": data.get("auth_parameters", 0),
            },
        )

    def _extract_cookies(
        self,
        target_url: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract cookie data."""
        if not data:
            return

        cookies = data.get("cookies", [])
        session_cookies = [c for c in cookies if "session" in c.get("name", "").lower()]

        self._add_observation(
            "cookies_discovered",
            f"Found {len(cookies)} cookies on {target_url}",
            {
                "target": target_url,
                "cookies": cookies,
                "session_cookies": len(session_cookies),
            },
        )

        # Update auth info
        if session_cookies:
            if "session_management" not in self._auth_info:
                self._auth_info["session_management"] = []
            self._auth_info["session_management"].append({
                "type": "cookie",
                "cookies": [c.get("name") for c in session_cookies],
                "httponly": all(c.get("httponly") for c in session_cookies),
                "secure": all(c.get("secure") for c in session_cookies),
            })

    def _extract_headers(
        self,
        target_url: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract header data."""
        if not data:
            return

        security_headers = data.get("security_headers", {})
        self._add_observation(
            "headers_analyzed",
            f"Analyzed security headers for {target_url}",
            {
                "target": target_url,
                "present": security_headers.get("present", []),
                "missing": security_headers.get("missing", []),
            },
        )

    def _extract_passive_issues(
        self,
        target_url: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract passive scan issues."""
        if not data:
            return

        issues = data.get("issues", [])
        if issues:
            self._add_observation(
                "passive_scan_issues",
                f"Found {len(issues)} passive scan issues on {target_url}",
                {
                    "target": target_url,
                    "issues": issues,
                },
            )

    def _analyze_input_points(self) -> None:
        """Analyze collected input points."""
        if not self._input_points:
            return

        # Categorize input points
        forms = [ip for ip in self._input_points if ip.get("type") == "form"]
        apis = [ip for ip in self._input_points if ip.get("type") == "api"]
        file_uploads = [ip for ip in self._input_points if ip.get("has_file_upload")]

        self._record_decision(
            "input_point_analysis",
            f"Analyzed {len(self._input_points)} input points",
            f"Found {len(forms)} forms, {len(apis)} API endpoints, {len(file_uploads)} file uploads",
            outputs={
                "total_input_points": len(self._input_points),
                "forms": len(forms),
                "apis": len(apis),
                "file_uploads": len(file_uploads),
            },
        )

    def _analyze_authentication(self) -> None:
        """Analyze authentication mechanisms."""
        # Find login forms
        login_forms = [ip for ip in self._input_points if ip.get("is_login_form")]

        # Find auth-required endpoints
        auth_endpoints = [ep for ep in self._endpoints if ep.get("auth_required")]

        # Determine auth mechanisms
        mechanisms: Set[str] = set()

        if login_forms:
            mechanisms.add("form_based")
            self._auth_info["login_forms"] = [
                {"url": f.get("url"), "fields": f.get("fields")}
                for f in login_forms
            ]

        if self._auth_info.get("session_management"):
            mechanisms.add("session_cookie")

        # Check for API auth (Bearer tokens, API keys)
        for ep in self._endpoints:
            for param in ep.get("parameters", []):
                if param.get("name") in ["Authorization", "api_key", "apikey", "token"]:
                    mechanisms.add("api_token")
                    break

        self._auth_info["mechanisms"] = list(mechanisms)
        self._auth_info["auth_required_endpoints"] = len(auth_endpoints)
        self._auth_info["public_endpoints"] = len(self._endpoints) - len(auth_endpoints)

        if mechanisms:
            self._record_decision(
                "auth_analysis",
                f"Identified {len(mechanisms)} authentication mechanisms",
                f"Detected: {', '.join(mechanisms)}",
                outputs=self._auth_info,
            )

    def _add_evidence(self, result: MCPResult) -> None:
        """Add evidence from MCP result."""
        self._evidences.append(result.to_evidence())

    def _add_observation(
        self,
        obs_type: str,
        description: str,
        data: Dict[str, Any],
    ) -> None:
        """Add observation record."""
        observation = {
            "observation_id": f"obs-{uuid.uuid4().hex[:8]}",
            "type": obs_type,
            "description": description,
            "data": data,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "agent": self.agent_type.value,
        }
        self._observations.append(observation)

    def _generate_operations(self) -> List[PatchOperation]:
        """Generate patch operations from collected data."""
        operations = []

        # Add evidence operations
        for evidence in self._evidences:
            operations.append(PatchOperation(
                op=OperationType.ADD_EVIDENCE,
                target="evidence",
                payload=evidence,
            ))

        # Add observation operations
        for observation in self._observations:
            operations.append(PatchOperation(
                op=OperationType.ADD_OBSERVATION,
                target="observations",
                payload=observation,
            ))

        # Update target profile with input points and auth info
        if self._input_points or self._auth_info:
            operations.append(PatchOperation(
                op=OperationType.UPDATE_TARGET_PROFILE,
                target="target_profile",
                payload={
                    "input_points": self._input_points,
                    "endpoints": self._endpoints,
                    "auth_info": self._auth_info,
                    "updated_at": datetime.utcnow().isoformat() + "Z",
                },
            ))

        return operations

    def _should_skip(self, context: AgentContext) -> Optional[str]:
        """Check if enumeration should be skipped."""
        # Check if we already have comprehensive enumeration data
        target_profile = context.target_profile or {}

        input_points = target_profile.get("input_points", [])
        endpoints = target_profile.get("endpoints", [])

        if len(input_points) >= 10 and len(endpoints) >= 5:
            auth_info = target_profile.get("auth_info", {})
            if auth_info.get("mechanisms"):
                return "Comprehensive enumeration data already exists"

        return None
