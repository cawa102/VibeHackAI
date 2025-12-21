"""
Nmap Passer - Normalizes Nmap scan output into common schema objects.

Parses Nmap XML output and converts it to TargetProfile and Observation objects.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union

from .base import BasePasser, MCPType, PasserRegistry, PasserResult
from ..schemas import TargetProfile, Observation
from ..schemas.target_profile import PortInfo, ServiceInfo, OSInfo


@PasserRegistry.register
class NmapPasser(BasePasser):
    """
    Passer for Nmap scan output.

    Handles XML format from Nmap scans and converts to TargetProfile/Observation.
    """

    mcp_type = MCPType.NMAP
    tool_name = "nmap"

    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """Check if this is Nmap XML output."""
        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, str):
            return "<?xml" in raw_output and "nmaprun" in raw_output

        if isinstance(raw_output, dict):
            return raw_output.get("source") == "nmap" or "nmaprun" in raw_output

        return False

    def normalize(
        self,
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize Nmap XML output.

        Args:
            raw_output: Nmap XML string, bytes, or pre-parsed dict.
            **kwargs: Additional parameters.

        Returns:
            PasserResult with TargetProfile and Observation objects.
        """
        result = self._create_result()

        # Handle different input types
        if isinstance(raw_output, bytes):
            raw_output = raw_output.decode("utf-8", errors="ignore")

        if isinstance(raw_output, dict):
            # Pre-parsed output
            return self._normalize_dict(raw_output, result)

        # Parse XML
        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as e:
            result.add_error(f"Failed to parse Nmap XML: {e}")
            return result

        return self._normalize_xml(root, result)

    def _normalize_xml(
        self,
        root: ET.Element,
        result: PasserResult,
    ) -> PasserResult:
        """Normalize from XML ElementTree."""
        # Get scan info for observation
        scan_info = self._extract_scan_info(root)

        # Process each host
        for host in root.findall(".//host"):
            target_profile = self._parse_host(host, result)
            if target_profile:
                result.target_profiles.append(target_profile)

        # Create observation for the scan
        observation = self._create_observation(scan_info, result)
        if observation:
            result.observations.append(observation)

        return result

    def _normalize_dict(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> PasserResult:
        """Normalize from pre-parsed dictionary."""
        # Handle hosts array
        hosts = data.get("hosts", [])
        if isinstance(hosts, list):
            for host_data in hosts:
                target_profile = self._parse_host_dict(host_data, result)
                if target_profile:
                    result.target_profiles.append(target_profile)

        # Create observation
        observation = self._create_observation(data, result)
        if observation:
            result.observations.append(observation)

        return result

    def _extract_scan_info(self, root: ET.Element) -> Dict[str, Any]:
        """Extract scan metadata from nmaprun element."""
        info = {}

        # Scan arguments
        info["args"] = root.get("args", "")
        info["scanner"] = root.get("scanner", "nmap")
        info["start"] = root.get("start", "")
        info["startstr"] = root.get("startstr", "")

        # Scan type from scaninfo
        scaninfo = root.find("scaninfo")
        if scaninfo is not None:
            info["type"] = scaninfo.get("type", "")
            info["protocol"] = scaninfo.get("protocol", "")
            info["services"] = scaninfo.get("services", "")

        # Run stats
        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            if finished is not None:
                info["elapsed"] = finished.get("elapsed", "")
                info["exit"] = finished.get("exit", "")

            hosts_stat = runstats.find("hosts")
            if hosts_stat is not None:
                info["hosts_up"] = hosts_stat.get("up", "0")
                info["hosts_down"] = hosts_stat.get("down", "0")
                info["hosts_total"] = hosts_stat.get("total", "0")

        return info

    def _parse_host(
        self,
        host: ET.Element,
        result: PasserResult,
    ) -> Optional[TargetProfile]:
        """Parse a host element into TargetProfile."""
        # Get host status
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            result.add_warning(f"Host is not up: {status.get('state')}")
            return None

        # Get addresses
        ip_address = None
        mac_address = None
        for addr in host.findall("address"):
            addr_type = addr.get("addrtype")
            if addr_type == "ipv4" or addr_type == "ipv6":
                ip_address = addr.get("addr")
            elif addr_type == "mac":
                mac_address = addr.get("addr")

        if not ip_address:
            result.add_warning("Host has no IP address")
            return None

        # Get hostnames
        hostnames = []
        for hostname in host.findall(".//hostname"):
            name = hostname.get("name")
            if name:
                hostnames.append(name)

        # Get ports
        ports = self._parse_ports(host, result)

        # Get OS info
        os_info = self._parse_os(host, result)

        # Build TargetProfile
        try:
            target_profile = TargetProfile(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                ip_address=ip_address,
                hostnames=hostnames,
                mac_address=mac_address,
                ports=ports,
                os_info=os_info,
            )
            return target_profile
        except Exception as e:
            result.add_error(f"Failed to create TargetProfile: {e}")
            return None

    def _parse_ports(
        self,
        host: ET.Element,
        result: PasserResult,
    ) -> List[PortInfo]:
        """Parse port information from host element."""
        ports = []

        for port in host.findall(".//port"):
            port_id = self._safe_int(port.get("portid"), result=result)
            protocol = port.get("protocol", "tcp")

            # Get state
            state_elem = port.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

            # Get service info
            service_elem = port.find("service")
            service = None
            if service_elem is not None:
                service = ServiceInfo(
                    name=service_elem.get("name", "unknown"),
                    product=service_elem.get("product"),
                    version=service_elem.get("version"),
                    extra_info=service_elem.get("extrainfo"),
                    tunnel=service_elem.get("tunnel"),
                    method=service_elem.get("method"),
                    confidence=self._safe_int(
                        service_elem.get("conf"), 0, result
                    ),
                )

            port_info = PortInfo(
                port=port_id,
                protocol=protocol,
                state=state,
                service=service,
            )
            ports.append(port_info)

        return ports

    def _parse_os(
        self,
        host: ET.Element,
        result: PasserResult,
    ) -> Optional[OSInfo]:
        """Parse OS detection information."""
        os_elem = host.find("os")
        if os_elem is None:
            return None

        # Get best OS match
        osmatch = os_elem.find("osmatch")
        if osmatch is None:
            return None

        name = osmatch.get("name", "")
        accuracy = self._safe_int(osmatch.get("accuracy"), 0, result)

        # Get OS class details
        osclass = osmatch.find("osclass")
        os_family = None
        os_vendor = None
        os_gen = None

        if osclass is not None:
            os_family = osclass.get("osfamily")
            os_vendor = osclass.get("vendor")
            os_gen = osclass.get("osgen")

        return OSInfo(
            name=name,
            family=os_family,
            vendor=os_vendor,
            generation=os_gen,
            accuracy=accuracy,
        )

    def _parse_host_dict(
        self,
        data: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[TargetProfile]:
        """Parse host data from dictionary format."""
        ip_address = data.get("ip") or data.get("address") or data.get("ip_address")
        if not ip_address:
            result.add_warning("Host data missing IP address")
            return None

        # Parse ports from dict
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

        # Parse OS from dict
        os_info = None
        os_data = data.get("os", {})
        if os_data:
            os_info = OSInfo(
                name=os_data.get("name", ""),
                family=os_data.get("family"),
                vendor=os_data.get("vendor"),
                accuracy=self._safe_int(os_data.get("accuracy"), 0, result),
            )

        try:
            return TargetProfile(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                ip_address=ip_address,
                hostnames=data.get("hostnames", []),
                mac_address=data.get("mac_address"),
                ports=ports,
                os_info=os_info,
            )
        except Exception as e:
            result.add_error(f"Failed to create TargetProfile from dict: {e}")
            return None

    def _create_observation(
        self,
        scan_info: Dict[str, Any],
        result: PasserResult,
    ) -> Optional[Observation]:
        """Create an Observation for the scan."""
        try:
            summary_parts = []
            if scan_info.get("hosts_up"):
                summary_parts.append(f"{scan_info['hosts_up']} hosts up")
            if scan_info.get("hosts_total"):
                summary_parts.append(f"{scan_info['hosts_total']} total")
            if scan_info.get("elapsed"):
                summary_parts.append(f"in {scan_info['elapsed']}s")

            summary = "Nmap scan completed"
            if summary_parts:
                summary += f": {', '.join(summary_parts)}"

            # Extract target profiles IDs for summary
            target_ids = [tp.id for tp in result.target_profiles]

            observation = Observation(
                session_id=self.session_id,
                scope_tag=self.scope_tag,
                created_by=self.created_by,
                tool=self.tool_name,
                action="scan",
                summary=summary,
                raw_output_preview=scan_info.get("args", "")[:500],
                exit_code=0 if scan_info.get("exit") == "success" else 1,
                success=scan_info.get("exit") == "success" or scan_info.get("exit") is None,
                metadata={
                    "scan_type": scan_info.get("type"),
                    "protocol": scan_info.get("protocol"),
                    "services_scanned": scan_info.get("services"),
                    "elapsed_seconds": scan_info.get("elapsed"),
                    "target_profile_ids": target_ids,
                },
            )
            return observation
        except Exception as e:
            result.add_error(f"Failed to create Observation: {e}")
            return None
