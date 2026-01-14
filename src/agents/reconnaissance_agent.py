"""
Reconnaissance Agent for PentestAgent.

Performs passive OSINT and minimal active reconnaissance.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .base_agent import (
    BaseAgent,
    AgentConfig,
    AgentContext,
    AgentOutput,
    AgentType,
)
from ..mcp_adapters.shodan_adapter import ShodanAdapter
from ..mcp_adapters.osint_adapter import OSINTAdapter
from ..mcp_adapters.nmap_adapter import NmapAdapter
from ..mcp_adapters.base_adapter import MCPResult
from ..patch.patch import Patch, PatchOperation
from ..patch.operations import OperationType


class ReconnaissanceAgent(BaseAgent):
    """
    Reconnaissance Agent.

    Responsibilities:
    - Passive reconnaissance via Shodan
    - OSINT collection (DNS, WHOIS, subdomains)
    - Minimal active scanning via Nmap when needed
    - Target profile generation
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        shodan_adapter: Optional[ShodanAdapter] = None,
        osint_adapter: Optional[OSINTAdapter] = None,
        nmap_adapter: Optional[NmapAdapter] = None,
        mock_mode: bool = False,
    ):
        """
        Initialize Reconnaissance Agent.

        Args:
            config: Agent configuration.
            shodan_adapter: Shodan MCP adapter.
            osint_adapter: OSINT MCP adapter.
            nmap_adapter: Nmap MCP adapter.
            mock_mode: If True, use mock adapters.
        """
        if config is None:
            config = AgentConfig(
                agent_type=AgentType.RECON,
                timeout_seconds=600,  # 10 minutes
            )

        super().__init__(config)

        # Initialize adapters
        self.shodan = shodan_adapter or ShodanAdapter(mock_mode=mock_mode)
        self.osint = osint_adapter or OSINTAdapter(mock_mode=mock_mode)
        self.nmap = nmap_adapter or NmapAdapter(mock_mode=mock_mode)

        # Results storage
        self._evidences: List[Dict[str, Any]] = []
        self._observations: List[Dict[str, Any]] = []
        self._target_updates: Dict[str, Any] = {}

    def _execute(self, context: AgentContext) -> AgentOutput:
        """
        Execute reconnaissance.

        Args:
            context: Agent context.

        Returns:
            AgentOutput with results.
        """
        self._evidences = []
        self._observations = []
        self._target_updates = {}

        # Get targets from scope
        targets = self._extract_targets(context.scope)
        if not targets:
            return self._create_error_output(context, "No targets found in scope")

        self._record_decision(
            "target_selection",
            f"Processing {len(targets)} targets",
            f"Extracted {len(targets)} targets from scope",
            inputs={"scope": context.scope},
            outputs={"targets": targets},
        )

        # Process each target
        targets_found = 0
        for target_type, target_value in targets:
            try:
                if target_type == "ip":
                    self._process_ip_target(target_value)
                    targets_found += 1
                elif target_type == "cidr":
                    self._process_cidr_target(target_value)
                    targets_found += 1
                elif target_type == "domain":
                    self._process_domain_target(target_value)
                    targets_found += 1
                elif target_type == "url":
                    self._process_url_target(target_value)
                    targets_found += 1
            except Exception as e:
                self._add_warning(f"Failed to process {target_value}: {str(e)}")

        # Check if we need Nmap (active scan)
        nmap_needed = self._should_run_nmap()
        if nmap_needed:
            self._record_decision(
                "active_scan",
                "Running Nmap for additional port discovery",
                nmap_needed,
            )
            for target_type, target_value in targets:
                if target_type in ("ip", "domain"):
                    self._run_nmap_scan(target_value)
        else:
            self._record_decision(
                "skip_active_scan",
                "Skipping Nmap - sufficient passive data",
                "Passive reconnaissance provided sufficient information",
            )

        # Generate patch
        operations = self._generate_operations()
        patch = self._create_patch(context, operations)

        # Create phase result
        phase_result = {
            "targets_found": targets_found,
            "evidences_collected": len(self._evidences),
            "observations_made": len(self._observations),
            "nmap_used": nmap_needed is not None,
        }

        return self._create_success_output(context, patch, phase_result)

    def _extract_targets(
        self,
        scope: Optional[Dict[str, Any]],
    ) -> List[Tuple[str, str]]:
        """
        Extract targets from scope.

        Args:
            scope: Scope configuration.

        Returns:
            List of (type, value) tuples.
        """
        if not scope:
            return []

        targets = []
        for target in scope.get("targets", []):
            target_type = target.get("type", "unknown")
            target_value = target.get("value", "")
            if target_value:
                targets.append((target_type, target_value))

        return targets

    def _process_ip_target(self, ip: str) -> None:
        """
        Process an IP target.

        Args:
            ip: IP address to process.
        """
        # Shodan lookup (passive)
        shodan_result = self.shodan.host_lookup(ip)
        if shodan_result.success:
            self._add_evidence(shodan_result)
            self._extract_shodan_data(ip, shodan_result.data)

        # Get vulnerabilities
        vuln_result = self.shodan.get_vulns(ip)
        if vuln_result.success and vuln_result.data:
            self._add_evidence(vuln_result)
            self._extract_vulns(ip, vuln_result.data)

    def _process_cidr_target(self, cidr: str) -> None:
        """
        Process a CIDR target.

        Args:
            cidr: CIDR notation network.
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)

            # For large networks, sample
            if network.num_addresses > 256:
                self._add_warning(
                    f"Large network {cidr} ({network.num_addresses} hosts). "
                    "Consider sampling."
                )
                # Sample first few and last few
                hosts = list(network.hosts())[:5] + list(network.hosts())[-5:]
            else:
                hosts = list(network.hosts())[:50]  # Limit to 50

            for host in hosts:
                self._process_ip_target(str(host))

        except ValueError as e:
            self._add_warning(f"Invalid CIDR {cidr}: {e}")

    def _process_domain_target(self, domain: str) -> None:
        """
        Process a domain target.

        Args:
            domain: Domain to process.
        """
        # WHOIS lookup
        whois_result = self.osint.whois(domain)
        if whois_result.success:
            self._add_evidence(whois_result)
            self._extract_whois_data(domain, whois_result.data)

        # DNS records
        for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
            dns_result = self.osint.dns_lookup(domain, record_type)
            if dns_result.success:
                self._add_evidence(dns_result)
                self._extract_dns_data(domain, dns_result.data)

        # Subdomain enumeration
        subdomain_result = self.osint.enumerate_subdomains(domain)
        if subdomain_result.success:
            self._add_evidence(subdomain_result)
            self._extract_subdomains(domain, subdomain_result.data)

        # Certificate transparency
        cert_result = self.osint.search_certificates(domain)
        if cert_result.success:
            self._add_evidence(cert_result)
            self._extract_cert_data(domain, cert_result.data)

        # Technology detection
        tech_result = self.osint.detect_technologies(domain)
        if tech_result.success:
            self._add_evidence(tech_result)
            self._extract_tech_data(domain, tech_result.data)

        # Resolve domain to IP and process
        resolve_result = self.shodan.dns_resolve([domain])
        if resolve_result.success and resolve_result.data:
            for hostname, ip in resolve_result.data.items():
                if ip:
                    self._add_observation(
                        "dns_resolution",
                        f"Resolved {hostname} to {ip}",
                        {"hostname": hostname, "ip": ip},
                    )
                    self._process_ip_target(ip)

    def _process_url_target(self, url: str) -> None:
        """
        Process a URL target.

        Args:
            url: URL to process.
        """
        # Extract domain from URL
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]

        if domain:
            # Remove port if present
            domain = domain.split(':')[0]
            self._process_domain_target(domain)

    def _extract_shodan_data(
        self,
        ip: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract data from Shodan response."""
        if not data:
            return

        # Add observation for host discovery
        self._add_observation(
            "host_discovery",
            f"Discovered host {ip} via Shodan",
            {
                "ip": ip,
                "os": data.get("os"),
                "org": data.get("org"),
                "asn": data.get("asn"),
                "country": data.get("country_code"),
            },
        )

        # Extract port/service information
        for service in data.get("data", []):
            port = service.get("port")
            product = service.get("product", "unknown")
            version = service.get("version", "")

            self._add_observation(
                "service_discovery",
                f"Found {product} {version} on {ip}:{port}",
                {
                    "ip": ip,
                    "port": port,
                    "protocol": service.get("transport", "tcp"),
                    "service": product,
                    "version": version,
                    "banner": service.get("banner", "")[:200],
                    "cpe": service.get("cpe", []),
                },
            )

        # Update target profile
        self._update_target_profile(ip, {
            "ip": ip,
            "os": data.get("os"),
            "organization": data.get("org"),
            "asn": data.get("asn"),
            "country": data.get("country_code"),
            "hostnames": data.get("hostnames", []),
            "ports": data.get("ports", []),
        })

    def _extract_vulns(
        self,
        ip: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract vulnerability data from Shodan."""
        if not data:
            return

        vulns = data.get("vulns", [])
        if vulns:
            self._add_observation(
                "vulnerability_intel",
                f"Found {len(vulns)} potential vulnerabilities for {ip}",
                {
                    "ip": ip,
                    "cves": vulns,
                    "source": "shodan",
                },
            )

    def _extract_whois_data(
        self,
        domain: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract WHOIS data."""
        if not data:
            return

        self._add_observation(
            "whois_info",
            f"WHOIS information for {domain}",
            {
                "domain": domain,
                "registrar": data.get("registrar"),
                "creation_date": data.get("creation_date"),
                "expiration_date": data.get("expiration_date"),
                "name_servers": data.get("name_servers", []),
                "registrant_org": data.get("registrant", {}).get("organization"),
            },
        )

    def _extract_dns_data(
        self,
        domain: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract DNS data."""
        if not data:
            return

        record_type = data.get("type", "A")
        records = data.get("records", [])

        if records:
            self._add_observation(
                "dns_record",
                f"DNS {record_type} records for {domain}",
                {
                    "domain": domain,
                    "type": record_type,
                    "records": records,
                },
            )

    def _extract_subdomains(
        self,
        domain: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract subdomain data."""
        if not data:
            return

        subdomains = data.get("subdomains", [])
        if subdomains:
            self._add_observation(
                "subdomain_enumeration",
                f"Found {len(subdomains)} subdomains for {domain}",
                {
                    "domain": domain,
                    "subdomains": subdomains,
                },
            )

    def _extract_cert_data(
        self,
        domain: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract certificate transparency data."""
        if not data:
            return

        certs = data.get("certificates", [])
        if certs:
            self._add_observation(
                "certificate_info",
                f"Found {len(certs)} certificates for {domain}",
                {
                    "domain": domain,
                    "certificates": certs,
                },
            )

    def _extract_tech_data(
        self,
        domain: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract technology detection data."""
        if not data:
            return

        techs = data.get("technologies", {})
        if techs:
            self._add_observation(
                "technology_detection",
                f"Detected technologies for {domain}",
                {
                    "domain": domain,
                    "technologies": techs,
                },
            )

    def _should_run_nmap(self) -> Optional[str]:
        """
        Determine if Nmap scan is needed.

        Returns:
            Reason if Nmap is needed, None otherwise.
        """
        # Check if we have port information from passive sources
        has_port_info = any(
            obs.get("type") == "service_discovery"
            for obs in self._observations
        )

        if not has_port_info:
            return "No port information from passive sources"

        # Check if we have sufficient version info
        version_info_count = sum(
            1 for obs in self._observations
            if obs.get("type") == "service_discovery"
            and obs.get("data", {}).get("version")
        )

        if version_info_count < 2:
            return "Insufficient version information from passive sources"

        return None

    def _run_nmap_scan(self, target: str) -> None:
        """
        Run Nmap scan on target.

        Args:
            target: Target to scan.
        """
        # Use minimal/stealth scan
        result = self.nmap.stealth_scan(target, ports="22,80,443,8080,8443")

        if result.success:
            self._add_evidence(result)
            self._extract_nmap_data(target, result.data)

    def _extract_nmap_data(
        self,
        target: str,
        data: Optional[Dict[str, Any]],
    ) -> None:
        """Extract Nmap scan data."""
        if not data:
            return

        for port_info in data.get("ports", []):
            port = port_info.get("port")
            state = port_info.get("state")
            service = port_info.get("service", "unknown")

            self._add_observation(
                "port_scan",
                f"Port {port} is {state} on {target} (nmap)",
                {
                    "target": target,
                    "port": port,
                    "state": state,
                    "protocol": port_info.get("protocol", "tcp"),
                    "service": service,
                    "source": "nmap",
                },
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

    def _update_target_profile(
        self,
        target_id: str,
        data: Dict[str, Any],
    ) -> None:
        """Update target profile data."""
        if target_id not in self._target_updates:
            self._target_updates[target_id] = {}

        # Merge data
        existing = self._target_updates[target_id]
        for key, value in data.items():
            if value is not None:
                if isinstance(value, list) and key in existing:
                    # Merge lists
                    existing[key] = list(set(existing[key] + value))
                else:
                    existing[key] = value

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

        # Update target profile
        if self._target_updates:
            operations.append(PatchOperation(
                op=OperationType.UPDATE_TARGET_PROFILE,
                target="target_profile",
                payload={
                    "targets": self._target_updates,
                    "updated_at": datetime.utcnow().isoformat() + "Z",
                },
            ))

        return operations

    def _should_skip(self, context: AgentContext) -> Optional[str]:
        """Check if reconnaissance should be skipped."""
        # Check if we already have comprehensive target profile
        if context.target_profile:
            ports = context.target_profile.get("ports", [])
            services = context.target_profile.get("services", [])

            if len(ports) >= 5 and len(services) >= 3:
                return "Comprehensive target profile already exists"

        return None
