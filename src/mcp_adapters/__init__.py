"""
MCP Adapters module for VibeHackAI.

Provides adapters for various MCP (Model Context Protocol) tools.
"""

from .base_adapter import BaseMCPAdapter, MCPError, MCPResult
from .burp_adapter import BurpAdapter
from .cve_adapter import CVEAdapter
from .github_adapter import GitHubAdapter
from .kali_adapter import KaliAdapter
from .metasploit_adapter import MetasploitAdapter
from .nmap_adapter import NmapAdapter
from .osint_adapter import OSINTAdapter
from .shodan_adapter import ShodanAdapter
from .snyk_adapter import SnykAdapter

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
