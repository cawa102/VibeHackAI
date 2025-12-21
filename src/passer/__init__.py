"""
Passer - MCP output normalization engine for PentestAgent.

Converts various MCP server outputs into common schema objects.
"""

from __future__ import annotations

from .base import BasePasser, PasserError, PasserRegistry, PasserResult, normalize
from .burp_passer import BurpPasser
from .cve_passer import CvePasser
from .github_passer import GitHubPasser
from .kali_passer import KaliPasser
from .msf_passer import MetasploitPasser
from .nmap_passer import NmapPasser
from .osint_passer import OsintPasser
from .shodan_passer import ShodanPasser
from .snyk_passer import SnykPasser

__all__ = [
    # Base classes
    "BasePasser",
    "PasserError",
    "PasserResult",
    "PasserRegistry",
    "normalize",
    # Specific passers
    "NmapPasser",
    "ShodanPasser",
    "OsintPasser",
    "BurpPasser",
    "SnykPasser",
    "CvePasser",
    "GitHubPasser",
    "MetasploitPasser",
    "KaliPasser",
]
