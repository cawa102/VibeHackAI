"""
Passer - MCP output normalization engine for PentestAgent.

Converts hexstrike-ai and other MCP server outputs into common schema objects.

Passers are organized by tool category:
- ReconnaissancePasser: nmap, masscan, rustscan, amass, subfinder, dnsenum, autorecon
- EnumerationPasser: burpsuite, nikto, dirb, gobuster, ffuf, feroxbuster, dirsearch, enum4linux, smbmap
- ExploitationPasser: metasploit, sqlmap, hydra, msfvenom
- GitHubPasser: GitHub MCP (separate from hexstrike-ai)
"""

from __future__ import annotations

from .base import (
    BasePasser,
    PasserError,
    PasserResult,
    PasserRegistry,
    HexstrikeToolCategory,
    HexstrikeTool,
    TOOL_CATEGORY_MAP,
    detect_tool,
    normalize,
)
from .reconnaissance_passer import ReconnaissancePasser
from .enumeration_passer import EnumerationPasser
from .exploitation_passer import ExploitationPasser
from .github_passer import GitHubPasser

__all__ = [
    # Base classes and utilities
    "BasePasser",
    "PasserError",
    "PasserResult",
    "PasserRegistry",
    "HexstrikeToolCategory",
    "HexstrikeTool",
    "TOOL_CATEGORY_MAP",
    "detect_tool",
    "normalize",
    # Category-based passers
    "ReconnaissancePasser",
    "EnumerationPasser",
    "ExploitationPasser",
    "GitHubPasser",
]
