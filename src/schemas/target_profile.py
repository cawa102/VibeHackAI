"""
Target Profile schema for PentestAgent.

Defines the detailed information about targets discovered during reconnaissance.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional, Dict, Any, Union

from pydantic import BaseModel, Field

from .base import BaseSchema


class PortState(str, Enum):
    """Port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNKNOWN = "unknown"


class Protocol(str, Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class ServiceInfo(BaseModel):
    """Detailed service information."""

    name: str = Field(..., description="Service name")
    version: Optional[str] = Field(None, description="Service version")
    product: Optional[str] = Field(None, description="Product name")
    extra_info: Optional[str] = Field(None, description="Additional information")
    cpe: Optional[str] = Field(None, description="CPE identifier")
    tunnel: Optional[str] = Field(None, description="Tunnel type (ssl, etc.)")
    method: Optional[str] = Field(None, description="Detection method")
    banner: Optional[str] = Field(None, description="Service banner")
    confidence: int = Field(
        default=0,
        ge=0,
        le=10,
        description="Confidence level (0-10)",
    )


class OSInfo(BaseModel):
    """Operating system information."""

    name: str = Field(..., description="OS name")
    family: Optional[str] = Field(None, description="OS family (Linux, Windows, etc.)")
    vendor: Optional[str] = Field(None, description="OS vendor")
    generation: Optional[str] = Field(None, description="OS generation/version")
    accuracy: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Detection accuracy (0-100)",
    )


class PortInfo(BaseModel):
    """Information about a network port."""

    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: str = Field(default="tcp", description="Protocol (tcp, udp, sctp)")
    state: str = Field(default="unknown", description="Port state (open, closed, filtered)")
    service: Optional[ServiceInfo] = Field(None, description="Service information")
    banner: Optional[str] = Field(None, description="Service banner")
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs supporting this information",
    )


class TechnologyStack(BaseModel):
    """Technology stack information."""

    category: str = Field(..., description="Category (web_server, database, framework, etc.)")
    name: str = Field(..., description="Technology name")
    version: Optional[str] = Field(None, description="Version")
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs supporting this information",
    )


class HostInfo(BaseModel):
    """Information about a single host."""

    ip: str = Field(..., description="IP address")
    hostname: Optional[str] = Field(None, description="Hostname")
    hostnames: List[str] = Field(
        default_factory=list,
        description="List of associated hostnames",
    )
    os: Optional[str] = Field(None, description="Operating system")
    os_version: Optional[str] = Field(None, description="OS version")
    os_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="OS detection confidence (0.0-1.0)",
    )
    ports: List[PortInfo] = Field(
        default_factory=list,
        description="Open/discovered ports",
    )
    services: List[ServiceInfo] = Field(
        default_factory=list,
        description="Discovered services",
    )
    mac_address: Optional[str] = Field(None, description="MAC address")
    vendor: Optional[str] = Field(None, description="Hardware vendor")
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs for host discovery",
    )

    def get_port(self, port: int, protocol: str = "tcp") -> Optional[PortInfo]:
        """Get port info by port number and protocol."""
        for p in self.ports:
            if p.port == port and p.protocol == protocol:
                return p
        return None

    def add_port(self, port_info: PortInfo) -> None:
        """Add or update port information."""
        existing = self.get_port(port_info.port, port_info.protocol)
        if existing:
            # Update existing
            idx = self.ports.index(existing)
            self.ports[idx] = port_info
        else:
            self.ports.append(port_info)


class WebEndpoint(BaseModel):
    """Web application endpoint information."""

    url: str = Field(..., description="Full URL")
    method: str = Field(default="GET", description="HTTP method")
    parameters: List[str] = Field(
        default_factory=list,
        description="Parameter names",
    )
    content_type: Optional[str] = Field(None, description="Response content type")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    requires_auth: bool = Field(
        default=False,
        description="Whether endpoint requires authentication",
    )
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs (request/response captures)",
    )


class AuthenticationInfo(BaseModel):
    """Authentication mechanism information."""

    mechanism: str = Field(..., description="Auth mechanism (basic, form, oauth, jwt, etc.)")
    login_url: Optional[str] = Field(None, description="Login URL")
    logout_url: Optional[str] = Field(None, description="Logout URL")
    session_type: Optional[str] = Field(None, description="Session type (cookie, token, etc.)")
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs",
    )


class TargetProfile(BaseSchema):
    """
    Complete profile of discovered target information.

    Supports both single-host (flat) and multi-host (hosts list) formats.
    When ip_address is provided, it represents a single host.
    When hosts list is provided, it represents multiple hosts.
    """

    # Single-host format (flat)
    ip_address: Optional[str] = Field(
        None,
        description="IP address (single host format)",
    )
    hostnames: List[str] = Field(
        default_factory=list,
        description="Associated hostnames (single host format)",
    )
    mac_address: Optional[str] = Field(
        None,
        description="MAC address (single host format)",
    )
    ports: List[PortInfo] = Field(
        default_factory=list,
        description="Ports (single host format)",
    )
    os_info: Optional[OSInfo] = Field(
        None,
        description="OS information (single host format)",
    )
    tech_stack: List[str] = Field(
        default_factory=list,
        description="Technology stack as list of strings",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    # Multi-host format
    hosts: List[HostInfo] = Field(
        default_factory=list,
        description="Discovered hosts (multi-host format)",
    )
    technologies: List[TechnologyStack] = Field(
        default_factory=list,
        description="Discovered technology stack (structured)",
    )
    web_endpoints: List[WebEndpoint] = Field(
        default_factory=list,
        description="Discovered web endpoints",
    )
    authentication: List[AuthenticationInfo] = Field(
        default_factory=list,
        description="Authentication mechanisms",
    )
    dns_records: Dict[str, Any] = Field(
        default_factory=dict,
        description="DNS records (A, AAAA, MX, etc.)",
    )
    whois_info: Dict[str, Any] = Field(
        default_factory=dict,
        description="WHOIS information",
    )
    ssl_certificates: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="SSL/TLS certificate information",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes",
    )

    def get_host(self, ip: str) -> Optional[HostInfo]:
        """Get host info by IP address."""
        for host in self.hosts:
            if host.ip == ip:
                return host
        return None

    def add_host(self, host_info: HostInfo) -> None:
        """Add or update host information."""
        existing = self.get_host(host_info.ip)
        if existing:
            idx = self.hosts.index(existing)
            self.hosts[idx] = host_info
        else:
            self.hosts.append(host_info)

    def add_technology(self, tech: TechnologyStack) -> None:
        """Add technology to the stack."""
        # Avoid duplicates
        for existing in self.technologies:
            if existing.category == tech.category and existing.name == tech.name:
                return
        self.technologies.append(tech)

    def get_all_open_ports(self) -> List[tuple]:
        """Get all open ports across all hosts."""
        ports = []
        # From hosts list
        for host in self.hosts:
            for port in host.ports:
                if port.state == "open":
                    ports.append((host.ip, port.port, port.protocol, port.service))
        # From single host format
        if self.ip_address:
            for port in self.ports:
                if port.state == "open":
                    ports.append((self.ip_address, port.port, port.protocol, port.service))
        return ports

    def to_host_info(self) -> Optional[HostInfo]:
        """Convert single-host format to HostInfo."""
        if not self.ip_address:
            return None
        return HostInfo(
            ip=self.ip_address,
            hostnames=self.hostnames,
            mac_address=self.mac_address,
            ports=self.ports,
            os=self.os_info.name if self.os_info else None,
            os_confidence=self.os_info.accuracy / 100.0 if self.os_info else 0.0,
        )
