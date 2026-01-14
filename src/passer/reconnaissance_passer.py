"""
Reconnaissance Passer - Normalizes hexstrike-ai reconnaissance tool outputs.

Handles outputs from: nmap, masscan, rustscan, amass, subfinder, dnsenum, autorecon
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from .base import (
    BasePasser,
    HexstrikeToolCategory,
    HexstrikeTool,
    PasserRegistry,
    PasserResult,
)
from ..schemas import TargetProfile, Observation
from ..schemas.target_profile import PortInfo, ServiceInfo, OSInfo


@PasserRegistry.register
class ReconnaissancePasser(BasePasser):
    """
    Passer for hexstrike-ai reconnaissance tools.

    Normalizes outputs from port scanners, subdomain discovery, and DNS tools.
    """

    category = HexstrikeToolCategory.RECONNAISSANCE
    supported_tools = [
        HexstrikeTool.NMAP,
        HexstrikeTool.NMAP_ADVANCED,
        HexstrikeTool.MASSCAN,
        HexstrikeTool.RUSTSCAN,
        HexstrikeTool.AMASS,
        HexstrikeTool.SUBFINDER,
        HexstrikeTool.DNSENUM,
        HexstrikeTool.AUTORECON,
    ]

    def normalize(
        self,
        raw_output: Dict[str, Any],
        tool: HexstrikeTool,
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize reconnaissance tool output.

        Args:
            raw_output: Raw output from hexstrike-ai.
            tool: The specific tool that generated the output.
            **kwargs: Additional parameters.

        Returns:
            PasserResult with TargetProfile and Observation objects.
        """
        result = self._create_result(tool)
        data = self._extract_result(raw_output)

        if tool in (HexstrikeTool.NMAP, HexstrikeTool.NMAP_ADVANCED):
            return self._normalize_nmap(data, result)
        elif tool == HexstrikeTool.MASSCAN:
            return self._normalize_masscan(data, result)
        elif tool == HexstrikeTool.RUSTSCAN:
            return self._normalize_rustscan(data, result)
        elif tool in (HexstrikeTool.AMASS, HexstrikeTool.SUBFINDER):
            return self._normalize_subdomain(data, tool, result)
        elif tool == HexstrikeTool.DNSENUM:
            return self._normalize_dnsenum(data, result)
        elif tool == HexstrikeTool.AUTORECON:
            return self._normalize_autorecon(data, result)
        else:
            result.add_warning(f"Unhandled reconnaissance tool: {tool}")
            result.raw_data = raw_output
            return result

    def _normalize_nmap(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize Nmap scan output."""
        result.raw_data = data

        # Check for XML output
        if isinstance(data, str) and "<?xml" in data and "nmaprun" in data:
            return self._parse_nmap_xml(data, result)

        # Handle JSON/dict format
        hosts = data.get("hosts", [])
        if not hosts and "host" in data:
            hosts = [data["host"]] if isinstance(data["host"], dict) else data["host"]

        for host_data in hosts:
            target_profile = self._parse_host_dict(host_data, result)
            if target_profile:
                result.target_profiles.append(target_profile)

        # Create scan observation
        observation = self._create_scan_observation(
            "nmap",
            data,
            len(result.target_profiles),
            result,
        )
        if observation:
            result.observations.append(observation)

        return result

    def _parse_nmap_xml(
        self,
        xml_data: str,
        result: PasserResult,
    ) -> PasserResult:
        """Parse Nmap XML format."""
        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError as e:
            result.add_error(f"Failed to parse Nmap XML: {e}")
            return result

        # Extract scan info
        scan_info = {
            "args": root.get("args", ""),
            "scanner": root.get("scanner", "nmap"),
            "start": root.get("start", ""),
        }

        # Process each host
        for host in root.findall(".//host"):
            target_profile = self._parse_nmap_host_xml(host, result)
            if target_profile:
                result.target_profiles.append(target_profile)

        # Run stats
        runstats = root.find("runstats")
        if runstats is not None:
            hosts_stat = runstats.find("hosts")
            if hosts_stat is not None:
                scan_info["hosts_up"] = hosts_stat.get("up", "0")
                scan_info["hosts_total"] = hosts_stat.get("total", "0")

        observation = self._create_scan_observation(
            "nmap",
            scan_info,
            len(result.target_profiles),
            result,
        )
        if observation:
            result.observations.append(observation)

        return result

    def _parse_nmap_host_xml(
        self,
        host: ET.Element,
        result: PasserResult,
    ) -> Optional[TargetProfile]:
        """Parse Nmap host XML element."""
        # Check status
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            return None

        # Get addresses
        ip_address = None
        mac_address = None
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type in ("ipv4", "ipv6"):
                ip_address = addr.get("addr")
            elif addr_type == "mac":
                mac_address = addr.get("addr")

        if not ip_address:
            return None

        # Get hostnames
        hostnames = [
            h.get("name") for h in host.findall(".//hostname")
            if h.get("name")
        ]

        # Get ports
        ports = []
        for port in host.findall(".//port"):
            port_id = self._safe_int(port.get("portid"), result=result)
            protocol = port.get("protocol", "tcp")

            state_elem = port.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

            service_elem = port.find("service")
            service = None
            if service_elem is not None:
                service = ServiceInfo(
                    name=service_elem.get("name", "unknown"),
                    product=service_elem.get("product"),
                    version=service_elem.get("version"),
                    extra_info=service_elem.get("extrainfo"),
                )

            ports.append(PortInfo(
                port=port_id,
                protocol=protocol,
                state=state,
                service=service,
            ))

        # Get OS info
        os_info = None
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                osclass = osmatch.find("osclass")
                os_info = OSInfo(
                    name=osmatch.get("name", ""),
                    family=osclass.get("osfamily") if osclass is not None else None,
                    vendor=osclass.get("vendor") if osclass is not None else None,
                    accuracy=self._safe_int(osmatch.get("accuracy"), 0, result),
                )

        try:
            return TargetProfile(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                ip_address=ip_address,
                hostnames=hostnames,
                mac_address=mac_address,
                ports=ports,
                os_info=os_info,
            )
        except Exception as e:
            result.add_error(f"Failed to create TargetProfile: {e}")
            return None

    def _normalize_masscan(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize Masscan output."""
        result.raw_data = data

        # Masscan outputs list of host:port discoveries
        hosts_map: Dict[str, List[PortInfo]] = {}

        discoveries = data.get("discoveries", data.get("results", []))
        for item in discoveries:
            ip = item.get("ip") or item.get("address")
            if not ip:
                continue

            port = self._safe_int(item.get("port"), result=result)
            protocol = item.get("protocol", "tcp")
            state = item.get("state", "open")

            port_info = PortInfo(
                port=port,
                protocol=protocol,
                state=state,
            )

            if ip not in hosts_map:
                hosts_map[ip] = []
            hosts_map[ip].append(port_info)

        # Create TargetProfiles
        for ip, ports in hosts_map.items():
            try:
                target_profile = TargetProfile(
                    session_id=self.session_id,
                    scope_tag=self.scope_tag,
                    created_by=self.created_by,
                    ip_address=ip,
                    ports=ports,
                )
                result.target_profiles.append(target_profile)
            except Exception as e:
                result.add_warning(f"Failed to create TargetProfile for {ip}: {e}")

        observation = self._create_scan_observation(
            "masscan",
            data,
            len(result.target_profiles),
            result,
        )
        if observation:
            result.observations.append(observation)

        return result

    def _normalize_rustscan(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize RustScan output."""
        result.raw_data = data

        # RustScan format is similar to masscan
        hosts = data.get("hosts", data.get("results", []))
        for host_data in hosts:
            target_profile = self._parse_host_dict(host_data, result)
            if target_profile:
                result.target_profiles.append(target_profile)

        observation = self._create_scan_observation(
            "rustscan",
            data,
            len(result.target_profiles),
            result,
        )
        if observation:
            result.observations.append(observation)

        return result

    def _normalize_subdomain(
        self,
        data: Dict[str, Any],
        tool: HexstrikeTool,
        result: PasserResult,
    ) -> PasserResult:
        """Normalize Amass/Subfinder output."""
        result.raw_data = data

        tool_name = "amass" if tool == HexstrikeTool.AMASS else "subfinder"

        # Subdomain discovery outputs list of domains
        subdomains = data.get("subdomains", data.get("domains", data.get("results", [])))

        if isinstance(subdomains, str):
            subdomains = subdomains.strip().split("\n")

        for subdomain in subdomains:
            if not subdomain or not isinstance(subdomain, str):
                continue

            subdomain = subdomain.strip()
            if not subdomain:
                continue

            # Create minimal TargetProfile for subdomain
            try:
                target_profile = TargetProfile(
                    session_id=self.session_id,
                    scope_tag=self.scope_tag,
                    created_by=self.created_by,
                    hostnames=[subdomain],
                )
                result.target_profiles.append(target_profile)
            except Exception as e:
                result.add_warning(f"Failed to create TargetProfile for {subdomain}: {e}")

        observation = Observation(
            session_id=self.session_id,
            scope_tag=self.scope_tag,
            created_by=self.created_by,
            tool=tool_name,
            action="subdomain_discovery",
            summary=f"{tool_name} discovered {len(result.target_profiles)} subdomains",
            success=True,
            metadata={
                "subdomain_count": len(result.target_profiles),
                "target_profile_ids": [tp.id for tp in result.target_profiles],
            },
        )
        result.observations.append(observation)

        return result

    def _normalize_dnsenum(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize DNSEnum output."""
        result.raw_data = data

        # DNSEnum provides DNS records and subdomains
        records = data.get("records", {})
        subdomains = data.get("subdomains", [])

        for subdomain in subdomains:
            try:
                target_profile = TargetProfile(
                    session_id=self.session_id,
                    scope_tag=self.scope_tag,
                    created_by=self.created_by,
                    hostnames=[subdomain] if isinstance(subdomain, str) else [subdomain.get("name", "")],
                    ip_address=subdomain.get("ip") if isinstance(subdomain, dict) else None,
                )
                result.target_profiles.append(target_profile)
            except Exception as e:
                result.add_warning(f"Failed to create TargetProfile: {e}")

        observation = Observation(
            session_id=self.session_id,
            scope_tag=self.scope_tag,
            created_by=self.created_by,
            tool="dnsenum",
            action="dns_enumeration",
            summary=f"DNSEnum found {len(result.target_profiles)} hosts",
            success=True,
            metadata={
                "records": records,
                "subdomain_count": len(subdomains),
            },
        )
        result.observations.append(observation)

        return result

    def _normalize_autorecon(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize AutoRecon output."""
        result.raw_data = data

        # AutoRecon provides comprehensive scan results
        targets = data.get("targets", data.get("hosts", []))
        for target in targets:
            target_profile = self._parse_host_dict(target, result)
            if target_profile:
                result.target_profiles.append(target_profile)

        # AutoRecon also provides service-specific findings
        findings = data.get("findings", [])
        for finding in findings:
            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool="autorecon",
                action="service_finding",
                summary=finding.get("summary", "AutoRecon finding"),
                success=True,
                metadata=finding,
            )
            result.observations.append(observation)

        summary_obs = self._create_scan_observation(
            "autorecon",
            data,
            len(result.target_profiles),
            result,
        )
        if summary_obs:
            result.observations.insert(0, summary_obs)

        return result

    def _parse_host_dict(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[TargetProfile]:
        """Parse host data from dictionary format."""
        ip_address = data.get("ip") or data.get("address") or data.get("ip_address")

        # Parse ports
        ports = []
        for port_data in data.get("ports", []):
            service = None
            service_data = port_data.get("service", {})
            if service_data:
                service = ServiceInfo(
                    name=service_data.get("name", "unknown"),
                    product=service_data.get("product"),
                    version=service_data.get("version"),
                    extra_info=service_data.get("extra_info"),
                )

            port_info = PortInfo(
                port=self._safe_int(port_data.get("port"), result=result),
                protocol=port_data.get("protocol", "tcp"),
                state=port_data.get("state", "unknown"),
                service=service,
            )
            ports.append(port_info)

        # Parse OS
        os_info = None
        os_data = data.get("os", {})
        if os_data:
            os_info = OSInfo(
                name=os_data.get("name", ""),
                family=os_data.get("family"),
                vendor=os_data.get("vendor"),
                accuracy=self._safe_int(os_data.get("accuracy"), 0, result),
            )

        # Need either IP or hostname
        hostnames = data.get("hostnames", [])
        if not ip_address and not hostnames:
            return None

        try:
            return TargetProfile(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                ip_address=ip_address,
                hostnames=hostnames,
                mac_address=data.get("mac_address"),
                ports=ports,
                os_info=os_info,
            )
        except Exception as e:
            result.add_error(f"Failed to create TargetProfile: {e}")
            return None

    def _create_scan_observation(
        self,
        tool_name: str,
        data: Dict[str, Any],
        host_count: int,
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create scan summary observation."""
        try:
            summary_parts = [f"{host_count} hosts discovered"]
            if data.get("elapsed"):
                summary_parts.append(f"in {data['elapsed']}s")

            return Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=tool_name,
                action="scan",
                summary=f"{tool_name} scan: " + ", ".join(summary_parts),
                success=True,
                metadata={
                    "hosts_discovered": host_count,
                    "target_profile_ids": [tp.id for tp in result.target_profiles],
                    "scan_args": data.get("args", data.get("command")),
                },
            )
        except Exception as e:
            result.add_warning(f"Failed to create observation: {e}")
            return None
