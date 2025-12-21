"""
Shodan Passer - Normalizes Shodan API output into common schema objects.

Parses Shodan JSON responses and converts to TargetProfile and Observation objects.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union

from .base import BasePasser, MCPType, PasserRegistry, PasserResult
from ..schemas import TargetProfile, Observation
from ..schemas.target_profile import PortInfo, ServiceInfo, OSInfo


@PasserRegistry.register
class ShodanPasser(BasePasser):
    """
    Passer for Shodan API output.

    Handles JSON responses from Shodan and converts to TargetProfile/Observation.
    """

    mcp_type = MCPType.SHODAN
    tool_name = "shodan"

    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """Check if this is Shodan API output."""
        data = self._parse_input(raw_output)
        if data is None:
            return False

        # Check for Shodan-specific fields
        shodan_indicators = ["ip_str", "data", "ports", "org", "isp", "asn"]
        return any(key in data for key in shodan_indicators)

    def normalize(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize Shodan API output.

        Args:
            raw_output: Shodan JSON response.
            **kwargs: Additional parameters.

        Returns:
            PasserResult with TargetProfile and Observation objects.
        """
        result = self._create_result()

        data = self._parse_input(raw_output)
        if data is None:
            result.add_error("Failed to parse Shodan output as JSON")
            return result

        result.raw_data = data

        # Handle host search results (array of hosts)
        if "matches" in data:
            for match in data["matches"]:
                target = self._parse_host(match, result)
                if target:
                    result.target_profiles.append(target)
        # Handle single host lookup
        elif "ip_str" in data:
            target = self._parse_host(data, result)
            if target:
                result.target_profiles.append(target)

        # Create observation
        observation = self._create_observation(data, result)
        if observation:
            result.observations.append(observation)

        return result

    def _parse_input(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Parse input into dictionary."""
        if isinstance(raw_output, dict):
            return raw_output

        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, str):
            try:
                return json.loads(raw_output)
            except json.JSONDecodeError:
                return None

        return None

    def _parse_host(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[TargetProfile]:
        """Parse Shodan host data into TargetProfile."""
        ip_address = data.get("ip_str")
        if not ip_address:
            result.add_warning("Shodan host missing ip_str")
            return None

        # Parse hostnames
        hostnames = data.get("hostnames", [])

        # Parse ports and services
        ports = self._parse_ports(data, result)

        # Parse OS info
        os_info = self._parse_os(data, result)

        # Build technology stack from data
        tech_stack = self._extract_tech_stack(data)

        try:
            target = TargetProfile(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                ip_address=ip_address,
                hostnames=hostnames,
                ports=ports,
                os_info=os_info,
                tech_stack=tech_stack,
                metadata={
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "asn": data.get("asn"),
                    "country_code": data.get("country_code"),
                    "city": data.get("city"),
                    "region_code": data.get("region_code"),
                    "latitude": data.get("latitude"),
                    "longitude": data.get("longitude"),
                    "last_update": data.get("last_update"),
                },
            )
            return target
        except Exception as e:
            result.add_error(f"Failed to create TargetProfile from Shodan: {e}")
            return None

    def _parse_ports(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> List[PortInfo]:
        """Parse port information from Shodan data."""
        ports = []

        # Handle 'data' array (per-service entries)
        for service_data in data.get("data", []):
            port = self._safe_int(service_data.get("port"), result=result)
            protocol = service_data.get("transport", "tcp")

            # Build service info from banner
            service = ServiceInfo(
                name=service_data.get("_shodan", {}).get("module", "unknown"),
                product=service_data.get("product"),
                version=service_data.get("version"),
                extra_info=service_data.get("info"),
                banner=service_data.get("data", "")[:1000],  # Limit banner size
            )

            port_info = PortInfo(
                port=port,
                protocol=protocol,
                state="open",  # Shodan only returns open ports
                service=service,
            )
            ports.append(port_info)

        # If no 'data' array, use 'ports' list
        if not ports and "ports" in data:
            for port_num in data["ports"]:
                port_info = PortInfo(
                    port=self._safe_int(port_num, result=result),
                    protocol="tcp",
                    state="open",
                )
                ports.append(port_info)

        return ports

    def _parse_os(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[OSInfo]:
        """Parse OS information from Shodan data."""
        os_name = data.get("os")
        if not os_name:
            return None

        return OSInfo(
            name=os_name,
            family=None,
            vendor=None,
        )

    def _extract_tech_stack(self, data: Dict[str, Any]) -> List[str]:
        """Extract technology stack from Shodan data."""
        tech_stack = []

        # Get tags
        tags = data.get("tags", [])
        if tags:
            tech_stack.extend(tags)

        # Get products from service banners
        for service_data in data.get("data", []):
            product = service_data.get("product")
            if product and product not in tech_stack:
                tech_stack.append(product)

            # Check for SSL/TLS
            if service_data.get("ssl"):
                if "TLS" not in tech_stack:
                    tech_stack.append("TLS")

            # Check for HTTP
            if service_data.get("http"):
                http_info = service_data["http"]
                server = http_info.get("server")
                if server and server not in tech_stack:
                    tech_stack.append(server)

        return tech_stack

    def _create_observation(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create an Observation for the Shodan query."""
        try:
            # Determine action type
            action = "host_lookup"
            if "matches" in data:
                action = "search"

            # Build summary
            summary_parts = []
            if "total" in data:
                summary_parts.append(f"{data['total']} results")
            if result.target_profiles:
                summary_parts.append(f"{len(result.target_profiles)} hosts processed")

            summary = f"Shodan {action}"
            if summary_parts:
                summary += f": {', '.join(summary_parts)}"

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action=action,
                summary=summary,
                success=True,
                metadata={
                    "query": data.get("query"),
                    "total_results": data.get("total"),
                    "target_profile_ids": [tp.id for tp in result.target_profiles],
                },
            )
            return observation
        except Exception as e:
            result.add_error(f"Failed to create Observation: {e}")
            return None
