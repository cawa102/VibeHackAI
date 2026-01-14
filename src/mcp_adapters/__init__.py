"""
MCP Adapters module for PentestAgent.

Provides adapters for MCP (Model Context Protocol) tools.

Current MCP configuration (.mcp.json):
- filesystem: Workspace and state file management
- github: PoC search, source code analysis
- hexstrike-ai: Integrated security tools (Shodan, OSINT, Nmap, Burp, Snyk, CVE, Metasploit, Kali)
"""

from .base_adapter import BaseMCPAdapter, MCPResult, MCPError
from .filesystem_adapter import FilesystemAdapter
from .github_adapter import GitHubAdapter

__all__ = [
    "BaseMCPAdapter",
    "MCPResult",
    "MCPError",
    "FilesystemAdapter",
    "GitHubAdapter",
]
