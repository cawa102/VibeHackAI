"""
OSINT Passer - Normalizes OSINT tool output into common schema objects.

Handles domain/DNS/WHOIS information and converts to TargetProfile/Observation.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union

from .base import BasePasser, MCPType, PasserRegistry, PasserResult
from ..schemas import TargetProfile, Observation


@PasserRegistry.register
class OsintPasser(BasePasser):
    """
    Passer for OSINT tool output.

    Handles domain, DNS, WHOIS, and organization information.
    """

    mcp_type = MCPType.OSINT
    tool_name = "osint"

    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """Check if this is OSINT output."""
        data = self._parse_input(raw_output)
        if data is None:
            return False

        # Check for OSINT-specific fields
        osint_indicators = [
            "domain", "dns_records", "whois", "subdomains",
            "mx_records", "ns_records", "a_records", "aaaa_records",
            "registrar", "name_servers", "organization"
        ]
        return any(key in data for key in osint_indicators)

    def normalize(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize OSINT output.

        Args:
            raw_output: OSINT tool output.
            **kwargs: Additional parameters.

        Returns:
            PasserResult with TargetProfile and Observation objects.
        """
        result = self._create_result()

        data = self._parse_input(raw_output)
        if data is None:
            result.add_error("Failed to parse OSINT output")
            return result

        result.raw_data = data

        # Parse domain information
        if "domain" in data or "domains" in data:
            self._parse_domains(data, result)

        # Parse subdomains
        if "subdomains" in data:
            self._parse_subdomains(data["subdomains"], result)

        # Parse IP addresses found
        if "ip_addresses" in data or "a_records" in data:
            self._parse_ip_addresses(data, result)

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

    def _parse_domains(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> None:
        """Parse domain information."""
        domains = data.get("domains", [])
        if not domains and "domain" in data:
            domains = [data["domain"]] if isinstance(data["domain"], str) else data["domain"]

        for domain_info in domains:
            if isinstance(domain_info, str):
                domain_info = {"domain": domain_info}

            target = self._create_domain_target(domain_info, data, result)
            if target:
                result.target_profiles.append(target)

    def _create_domain_target(
        self,
        domain_info: Dict[str, Any],
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[TargetProfile]:
        """Create TargetProfile from domain information."""
        domain = domain_info.get("domain") or domain_info.get("name")
        if not domain:
            return None

        # Get associated IP addresses
        ip_addresses = []
        a_records = data.get("a_records", []) or domain_info.get("a_records", [])
        if a_records:
            ip_addresses.extend(a_records)

        # Use first IP as primary, or generate placeholder
        ip_address = ip_addresses[0] if ip_addresses else f"domain:{domain}"

        # Extract DNS records
        dns_records = {
            "a": data.get("a_records", []),
            "aaaa": data.get("aaaa_records", []),
            "mx": data.get("mx_records", []),
            "ns": data.get("ns_records", []) or data.get("name_servers", []),
            "txt": data.get("txt_records", []),
            "cname": data.get("cname_records", []),
        }

        # Extract WHOIS info
        whois_info = data.get("whois", {})

        try:
            target = TargetProfile(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                ip_address=ip_address,
                hostnames=[domain],
                metadata={
                    "domain": domain,
                    "dns_records": dns_records,
                    "whois": whois_info,
                    "registrar": whois_info.get("registrar") or data.get("registrar"),
                    "creation_date": whois_info.get("creation_date"),
                    "expiration_date": whois_info.get("expiration_date"),
                    "organization": data.get("organization") or whois_info.get("org"),
                    "additional_ips": ip_addresses[1:] if len(ip_addresses) > 1 else [],
                },
            )
            return target
        except Exception as e:
            result.add_error(f"Failed to create TargetProfile for domain: {e}")
            return None

    def _parse_subdomains(
        self,
        subdomains: List[Any],
        result: PasserResult,
    ) -> None:
        """Parse subdomain information."""
        for subdomain in subdomains:
            if isinstance(subdomain, str):
                subdomain = {"name": subdomain}

            name = subdomain.get("name") or subdomain.get("subdomain")
            if not name:
                continue

            ip_address = subdomain.get("ip") or subdomain.get("ip_address") or f"subdomain:{name}"

            try:
                target = TargetProfile(
                    session_id=self.session_id,
                    scope_tag=self.scope_tag,
                    created_by=self.created_by,
                    ip_address=ip_address,
                    hostnames=[name],
                    metadata={
                        "subdomain": name,
                        "source": subdomain.get("source"),
                        "type": "subdomain",
                    },
                )
                result.target_profiles.append(target)
            except Exception as e:
                result.add_warning(f"Failed to create TargetProfile for subdomain {name}: {e}")

    def _parse_ip_addresses(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> None:
        """Parse IP addresses from OSINT data."""
        ip_addresses = data.get("ip_addresses", [])
        a_records = data.get("a_records", [])

        # Combine and deduplicate
        all_ips = set(ip_addresses) | set(a_records)

        # Check if we already have profiles for these IPs
        existing_ips = {tp.ip_address for tp in result.target_profiles}

        for ip in all_ips:
            if ip in existing_ips or ip.startswith("domain:") or ip.startswith("subdomain:"):
                continue

            try:
                target = TargetProfile(
                    session_id=self.session_id,
                    scope_tag=self.scope_tag,
                    created_by=self.created_by,
                    ip_address=ip,
                    hostnames=[],
                    metadata={
                        "source": "osint",
                        "type": "ip_address",
                    },
                )
                result.target_profiles.append(target)
            except Exception as e:
                result.add_warning(f"Failed to create TargetProfile for IP {ip}: {e}")

    def _create_observation(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create an Observation for the OSINT query."""
        try:
            # Determine what type of OSINT was performed
            actions = []
            if "domain" in data or "domains" in data:
                actions.append("domain_lookup")
            if "subdomains" in data:
                actions.append("subdomain_enum")
            if "whois" in data:
                actions.append("whois_lookup")
            if "dns_records" in data or any(k.endswith("_records") for k in data.keys()):
                actions.append("dns_lookup")

            action = "_".join(actions) if actions else "osint_lookup"

            # Build summary
            summary_parts = []
            if "domain" in data:
                summary_parts.append(f"domain: {data['domain']}")
            if "subdomains" in data:
                summary_parts.append(f"{len(data['subdomains'])} subdomains")
            if result.target_profiles:
                summary_parts.append(f"{len(result.target_profiles)} targets")

            summary = "OSINT reconnaissance"
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
                    "query_domain": data.get("domain"),
                    "subdomains_found": len(data.get("subdomains", [])),
                    "target_profile_ids": [tp.id for tp in result.target_profiles],
                },
            )
            return observation
        except Exception as e:
            result.add_error(f"Failed to create Observation: {e}")
            return None
