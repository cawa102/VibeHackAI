"""
Passer - MCP output normalization engine for PentestAgent.

Converts various MCP server outputs into common schema objects.
"""

from __future__ import annotations

from .base import (
    BasePasser,
    PasserError,
    PasserResult,
    PasserRegistry,
    normalize,
)
from .nmap_passer import NmapPasser
from .shodan_passer import ShodanPasser
from .osint_passer import OsintPasser
from .burp_passer import BurpPasser
from .snyk_passer import SnykPasser
from .cve_passer import CvePasser
from .github_passer import GitHubPasser
from .msf_passer import MetasploitPasser
from .kali_passer import KaliPasser

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
