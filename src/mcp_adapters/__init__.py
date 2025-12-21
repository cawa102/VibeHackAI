"""
MCP Adapters module for PentestAgent.

Provides adapters for various MCP (Model Context Protocol) tools.
"""

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError
from .shodan_adapter import ShodanAdapter
from .osint_adapter import OSINTAdapter
from .nmap_adapter import NmapAdapter
from .burp_adapter import BurpAdapter
from .snyk_adapter import SnykAdapter
from .cve_adapter import CVEAdapter
from .github_adapter import GitHubAdapter
from .metasploit_adapter import MetasploitAdapter
from .kali_adapter import KaliAdapter

__all__ = [
    "BaseMCPAdapter",
    "MCPResult",
    "MCPError",
    "ShodanAdapter",
    "OSINTAdapter",
    "NmapAdapter",
    "BurpAdapter",
    "SnykAdapter",
    "CVEAdapter",
    "GitHubAdapter",
    "MetasploitAdapter",
    "KaliAdapter",
]
