"""
Base Passer class and registry for hexstrike-ai output normalization.

Provides the foundation for converting hexstrike-ai tool outputs into common schema objects.

hexstrike-ai is an integrated security tools MCP that provides:
- Reconnaissance: nmap, amass, subfinder, masscan, rustscan
- Enumeration: burpsuite, nikto, dirb, gobuster, ffuf, feroxbuster
- Exploitation: metasploit, sqlmap, hydra
- Vulnerability: nuclei, snyk-like scanning
- OSINT: theharvester, recon-ng, shodan-cli
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Union

from ..schemas import (
    TargetProfile,
    Observation,
    VulnCandidate,
    ExploitCandidate,
    ExecutionResult,
)
from ..schemas.evidence import EvidenceItem

logger = logging.getLogger(__name__)


class HexstrikeToolCategory(str, Enum):
    """
    Categories of hexstrike-ai tools.

    Maps to the tool categories available in hexstrike-ai MCP.
    """
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    VULNERABILITY = "vulnerability"
    OSINT = "osint"
    GITHUB = "github"  # Separate MCP, not hexstrike-ai
    UNKNOWN = "unknown"


class HexstrikeTool(str, Enum):
    """
    Specific tools available in hexstrike-ai.

    These correspond to mcp__hexstrike-ai__<tool_name> functions.
    """
    # Reconnaissance
    NMAP = "nmap_scan"
    NMAP_ADVANCED = "nmap_advanced_scan"
    MASSCAN = "masscan_high_speed"
    RUSTSCAN = "rustscan_fast_scan"
    AMASS = "amass_scan"
    SUBFINDER = "subfinder_scan"
    DNSENUM = "dnsenum_scan"
    AUTORECON = "autorecon_scan"

    # Enumeration
    BURPSUITE = "burpsuite_scan"
    NIKTO = "nikto_scan"
    DIRB = "dirb_scan"
    GOBUSTER = "gobuster_scan"
    FFUF = "ffuf_scan"
    FEROXBUSTER = "feroxbuster_scan"
    DIRSEARCH = "dirsearch_scan"
    ENUM4LINUX = "enum4linux_scan"
    SMBMAP = "smbmap_scan"

    # Exploitation
    METASPLOIT = "metasploit_run"
    SQLMAP = "sqlmap_scan"
    HYDRA = "hydra_attack"
    MSFVENOM = "msfvenom_generate"

    # Vulnerability
    NUCLEI = "nuclei_scan"
    WPSCAN = "wpscan_analyze"

    # OSINT
    THEHARVESTER = "theharvester"  # via recon-ng
    SHODAN = "shodan_cli"  # if available

    # Unknown
    UNKNOWN = "unknown"


# Mapping from tool to category
TOOL_CATEGORY_MAP: Dict[HexstrikeTool, HexstrikeToolCategory] = {
    HexstrikeTool.NMAP: HexstrikeToolCategory.RECONNAISSANCE,
    HexstrikeTool.NMAP_ADVANCED: HexstrikeToolCategory.RECONNAISSANCE,
    HexstrikeTool.MASSCAN: HexstrikeToolCategory.RECONNAISSANCE,
    HexstrikeTool.RUSTSCAN: HexstrikeToolCategory.RECONNAISSANCE,
    HexstrikeTool.AMASS: HexstrikeToolCategory.RECONNAISSANCE,
    HexstrikeTool.SUBFINDER: HexstrikeToolCategory.RECONNAISSANCE,
    HexstrikeTool.DNSENUM: HexstrikeToolCategory.RECONNAISSANCE,
    HexstrikeTool.AUTORECON: HexstrikeToolCategory.RECONNAISSANCE,

    HexstrikeTool.BURPSUITE: HexstrikeToolCategory.ENUMERATION,
    HexstrikeTool.NIKTO: HexstrikeToolCategory.ENUMERATION,
    HexstrikeTool.DIRB: HexstrikeToolCategory.ENUMERATION,
    HexstrikeTool.GOBUSTER: HexstrikeToolCategory.ENUMERATION,
    HexstrikeTool.FFUF: HexstrikeToolCategory.ENUMERATION,
    HexstrikeTool.FEROXBUSTER: HexstrikeToolCategory.ENUMERATION,
    HexstrikeTool.DIRSEARCH: HexstrikeToolCategory.ENUMERATION,
    HexstrikeTool.ENUM4LINUX: HexstrikeToolCategory.ENUMERATION,
    HexstrikeTool.SMBMAP: HexstrikeToolCategory.ENUMERATION,

    HexstrikeTool.METASPLOIT: HexstrikeToolCategory.EXPLOITATION,
    HexstrikeTool.SQLMAP: HexstrikeToolCategory.EXPLOITATION,
    HexstrikeTool.HYDRA: HexstrikeToolCategory.EXPLOITATION,
    HexstrikeTool.MSFVENOM: HexstrikeToolCategory.EXPLOITATION,

    HexstrikeTool.NUCLEI: HexstrikeToolCategory.VULNERABILITY,
    HexstrikeTool.WPSCAN: HexstrikeToolCategory.VULNERABILITY,

    HexstrikeTool.THEHARVESTER: HexstrikeToolCategory.OSINT,
    HexstrikeTool.SHODAN: HexstrikeToolCategory.OSINT,

    HexstrikeTool.UNKNOWN: HexstrikeToolCategory.UNKNOWN,
}


class PasserError(Exception):
    """Exception raised when passer fails to normalize output."""

    def __init__(
        self,
        message: str,
        tool: Optional[HexstrikeTool] = None,
        partial_result: Optional[Any] = None,
    ):
        super().__init__(message)
        self.tool = tool
        self.partial_result = partial_result


@dataclass
class PasserResult:
    """
    Result of a passer normalization operation.

    Contains the normalized objects and any warnings/errors encountered.
    """

    success: bool = True
    target_profiles: List[TargetProfile] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    vuln_candidates: List[VulnCandidate] = field(default_factory=list)
    exploit_candidates: List[ExploitCandidate] = field(default_factory=list)
    execution_results: List[ExecutionResult] = field(default_factory=list)
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None
    unknown_fields: Dict[str, Any] = field(default_factory=dict)
    source_tool: Optional[HexstrikeTool] = None

    def has_warnings(self) -> bool:
        """Check if there are any warnings."""
        return len(self.warnings) > 0

    def has_errors(self) -> bool:
        """Check if there are any errors."""
        return len(self.errors) > 0

    def add_warning(self, warning: str) -> None:
        """Add a warning message."""
        self.warnings.append(warning)
        logger.warning(f"Passer warning: {warning}")

    def add_error(self, error: str) -> None:
        """Add an error message."""
        self.errors.append(error)
        self.success = False
        logger.error(f"Passer error: {error}")

    def merge(self, other: "PasserResult") -> "PasserResult":
        """Merge another PasserResult into this one."""
        self.target_profiles.extend(other.target_profiles)
        self.observations.extend(other.observations)
        self.vuln_candidates.extend(other.vuln_candidates)
        self.exploit_candidates.extend(other.exploit_candidates)
        self.execution_results.extend(other.execution_results)
        self.evidence_items.extend(other.evidence_items)
        self.warnings.extend(other.warnings)
        self.errors.extend(other.errors)
        self.unknown_fields.update(other.unknown_fields)
        if other.has_errors():
            self.success = False
        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "source_tool": self.source_tool.value if self.source_tool else None,
            "target_profiles": [tp.dict() for tp in self.target_profiles],
            "observations": [obs.dict() for obs in self.observations],
            "vuln_candidates": [vc.dict() for vc in self.vuln_candidates],
            "exploit_candidates": [ec.dict() for ec in self.exploit_candidates],
            "execution_results": [er.dict() for er in self.execution_results],
            "evidence_items": [ei.dict() for ei in self.evidence_items],
            "warnings": self.warnings,
            "errors": self.errors,
            "unknown_fields": self.unknown_fields,
        }


class BasePasser(ABC):
    """
    Abstract base class for hexstrike-ai output normalizers.

    Each tool category should have a corresponding Passer implementation
    that knows how to parse and normalize its output format.
    """

    # Tool category this passer handles
    category: HexstrikeToolCategory = HexstrikeToolCategory.UNKNOWN

    # Specific tools this passer can handle
    supported_tools: List[HexstrikeTool] = []

    def __init__(
        self,
        session_id: str,
        scope_tag: str,
        created_by: str = "passer",
    ):
        """
        Initialize the passer.

        Args:
            session_id: Current session ID.
            scope_tag: Scope tag for created objects.
            created_by: Creator identifier.
        """
        self.session_id = session_id
        self.scope_tag = scope_tag
        self.created_by = created_by

    @abstractmethod
    def normalize(
        self,
        raw_output: Dict[str, Any],
        tool: HexstrikeTool,
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize hexstrike-ai tool output into common schema objects.

        Args:
            raw_output: Raw output from hexstrike-ai (the 'result' field).
            tool: The specific tool that generated the output.
            **kwargs: Additional parameters.

        Returns:
            PasserResult containing normalized objects.
        """
        pass

    def can_handle(self, tool: HexstrikeTool) -> bool:
        """
        Check if this passer can handle the given tool.

        Args:
            tool: Tool to check.

        Returns:
            True if this passer can handle the tool.
        """
        return tool in self.supported_tools

    def _create_result(self, tool: HexstrikeTool) -> PasserResult:
        """Create a new PasserResult."""
        return PasserResult(source_tool=tool)

    def _extract_result(self, raw_output: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract the actual result from hexstrike-ai response.

        hexstrike-ai wraps results in a 'result' field.

        Args:
            raw_output: Raw hexstrike-ai response.

        Returns:
            The extracted result data.
        """
        if isinstance(raw_output, dict) and "result" in raw_output:
            return raw_output["result"]
        return raw_output

    def _safe_get(
        self,
        data: Dict[str, Any],
        key: str,
        default: Any = None,
        result: Optional[PasserResult] = None,
    ) -> Any:
        """Safely get a value from a dictionary."""
        value = data.get(key, default)
        if value is None and result is not None:
            result.add_warning(f"Missing field: {key}")
        return value

    def _safe_int(
        self,
        value: Any,
        default: int = 0,
        result: Optional[PasserResult] = None,
    ) -> int:
        """Safely convert a value to int."""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            if result is not None:
                result.add_warning(f"Could not convert '{value}' to int")
            return default

    def _safe_float(
        self,
        value: Any,
        default: float = 0.0,
        result: Optional[PasserResult] = None,
    ) -> float:
        """Safely convert a value to float."""
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            if result is not None:
                result.add_warning(f"Could not convert '{value}' to float")
            return default


class PasserRegistry:
    """
    Registry for Passer implementations.

    Allows registration and lookup of passers by tool or category.
    """

    _passers: Dict[HexstrikeToolCategory, Type[BasePasser]] = {}
    _tool_passers: Dict[HexstrikeTool, Type[BasePasser]] = {}

    @classmethod
    def register(cls, passer_class: Type[BasePasser]) -> Type[BasePasser]:
        """
        Register a passer class.

        Can be used as a decorator:
            @PasserRegistry.register
            class MyPasser(BasePasser):
                category = HexstrikeToolCategory.RECONNAISSANCE
                supported_tools = [HexstrikeTool.NMAP, ...]
        """
        cls._passers[passer_class.category] = passer_class
        for tool in passer_class.supported_tools:
            cls._tool_passers[tool] = passer_class
        logger.debug(f"Registered passer: {passer_class.category.value}")
        return passer_class

    @classmethod
    def get_by_category(cls, category: HexstrikeToolCategory) -> Optional[Type[BasePasser]]:
        """Get a passer class by category."""
        return cls._passers.get(category)

    @classmethod
    def get_by_tool(cls, tool: HexstrikeTool) -> Optional[Type[BasePasser]]:
        """Get a passer class by tool."""
        return cls._tool_passers.get(tool)

    @classmethod
    def get_all(cls) -> Dict[HexstrikeToolCategory, Type[BasePasser]]:
        """Get all registered passers."""
        return cls._passers.copy()


def detect_tool(tool_name: str) -> HexstrikeTool:
    """
    Detect the HexstrikeTool from a tool name string.

    Args:
        tool_name: The tool name (e.g., 'nmap_scan', 'burpsuite_scan').

    Returns:
        The corresponding HexstrikeTool enum value.
    """
    try:
        return HexstrikeTool(tool_name)
    except ValueError:
        return HexstrikeTool.UNKNOWN


def normalize(
    raw_output: Dict[str, Any],
    tool_name: str,
    session_id: str,
    scope_tag: str,
    created_by: str = "passer",
    **kwargs: Any,
) -> PasserResult:
    """
    Normalize hexstrike-ai tool output using the appropriate passer.

    This is the main entry point for normalizing hexstrike-ai outputs.

    Args:
        raw_output: Raw output from hexstrike-ai.
        tool_name: Name of the tool (e.g., 'nmap_scan').
        session_id: Current session ID.
        scope_tag: Scope tag for created objects.
        created_by: Creator identifier.
        **kwargs: Additional parameters for the passer.

    Returns:
        PasserResult containing normalized objects.
    """
    result = PasserResult()

    # Detect tool type
    tool = detect_tool(tool_name)
    if tool == HexstrikeTool.UNKNOWN:
        result.add_warning(f"Unknown tool: {tool_name}, using generic parsing")

    # Get the passer
    passer_class = PasserRegistry.get_by_tool(tool)
    if passer_class is None:
        # Try by category
        category = TOOL_CATEGORY_MAP.get(tool, HexstrikeToolCategory.UNKNOWN)
        passer_class = PasserRegistry.get_by_category(category)

    if passer_class is None:
        result.add_error(f"No passer registered for tool: {tool_name}")
        result.raw_data = raw_output
        return result

    # Create passer instance and normalize
    passer = passer_class(session_id, scope_tag, created_by)
    try:
        return passer.normalize(raw_output, tool, **kwargs)
    except Exception as e:
        result.add_error(f"Passer failed: {str(e)}")
        logger.exception(f"Passer for {tool_name} failed")
        result.raw_data = raw_output
        return result
