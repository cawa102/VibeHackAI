"""
Base Passer class and registry for MCP output normalization.

Provides the foundation for converting MCP server outputs into common schema objects.
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


class MCPType(str, Enum):
    """Supported MCP server types."""
    NMAP = "nmap"
    SHODAN = "shodan"
    OSINT = "osint"
    BURP = "burp"
    SNYK = "snyk"
    CVE = "cve"
    GITHUB = "github"
    GITLAB = "gitlab"
    METASPLOIT = "metasploit"
    KALI = "kali"
    UNKNOWN = "unknown"


class PasserError(Exception):
    """Exception raised when passer fails to normalize output."""

    def __init__(
        self,
        message: str,
        mcp_type: Optional[MCPType] = None,
        partial_result: Optional[Any] = None,
    ):
        super().__init__(message)
        self.mcp_type = mcp_type
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
    Abstract base class for MCP output normalizers.

    Each MCP type should have a corresponding Passer implementation
    that knows how to parse and normalize its output format.
    """

    # MCP type this passer handles
    mcp_type: MCPType = MCPType.UNKNOWN

    # Tool name for this passer
    tool_name: str = "unknown"

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
        raw_output: Union[str, bytes, Dict[str, Any]],
        **kwargs: Any,
    ) -> PasserResult:
        """
        Normalize MCP output into common schema objects.

        Args:
            raw_output: Raw output from the MCP server.
            **kwargs: Additional parameters.

        Returns:
            PasserResult containing normalized objects.
        """
        pass

    @abstractmethod
    def can_handle(self, raw_output: Union[str, bytes, Dict[str, Any]]) -> bool:
        """
        Check if this passer can handle the given output.

        Args:
            raw_output: Raw output to check.

        Returns:
            True if this passer can handle the output.
        """
        pass

    def _create_result(self) -> PasserResult:
        """Create a new PasserResult."""
        return PasserResult()

    def _safe_get(
        self,
        data: Dict[str, Any],
        key: str,
        default: Any = None,
        result: Optional[PasserResult] = None,
    ) -> Any:
        """
        Safely get a value from a dictionary.

        Args:
            data: Dictionary to get value from.
            key: Key to get.
            default: Default value if key not found.
            result: PasserResult to add warning to.

        Returns:
            Value or default.
        """
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
        """
        Safely convert a value to int.

        Args:
            value: Value to convert.
            default: Default value if conversion fails.
            result: PasserResult to add warning to.

        Returns:
            Integer value or default.
        """
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
        """
        Safely convert a value to float.

        Args:
            value: Value to convert.
            default: Default value if conversion fails.
            result: PasserResult to add warning to.

        Returns:
            Float value or default.
        """
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            if result is not None:
                result.add_warning(f"Could not convert '{value}' to float")
            return default

    def _collect_unknown_fields(
        self,
        data: Dict[str, Any],
        known_fields: List[str],
        result: PasserResult,
    ) -> None:
        """
        Collect unknown fields from data.

        Args:
            data: Data dictionary.
            known_fields: List of known field names.
            result: PasserResult to add unknown fields to.
        """
        for key, value in data.items():
            if key not in known_fields:
                result.unknown_fields[key] = value
                result.add_warning(f"Unknown field preserved: {key}")


class PasserRegistry:
    """
    Registry for Passer implementations.

    Allows registration and lookup of passers by MCP type.
    """

    _passers: Dict[MCPType, Type[BasePasser]] = {}

    @classmethod
    def register(cls, passer_class: Type[BasePasser]) -> Type[BasePasser]:
        """
        Register a passer class.

        Can be used as a decorator:
            @PasserRegistry.register
            class MyPasser(BasePasser):
                mcp_type = MCPType.NMAP

        Args:
            passer_class: Passer class to register.

        Returns:
            The registered class (for decorator use).
        """
        cls._passers[passer_class.mcp_type] = passer_class
        logger.debug(f"Registered passer: {passer_class.mcp_type.value}")
        return passer_class

    @classmethod
    def get(cls, mcp_type: MCPType) -> Optional[Type[BasePasser]]:
        """
        Get a passer class by MCP type.

        Args:
            mcp_type: MCP type to get passer for.

        Returns:
            Passer class or None if not found.
        """
        return cls._passers.get(mcp_type)

    @classmethod
    def get_all(cls) -> Dict[MCPType, Type[BasePasser]]:
        """Get all registered passers."""
        return cls._passers.copy()

    @classmethod
    def detect_type(
        cls,
        raw_output: Union[str, bytes, Dict[str, Any]],
        session_id: str,
        scope_tag: str,
    ) -> Optional[MCPType]:
        """
        Detect the MCP type from raw output.

        Args:
            raw_output: Raw output to detect type from.
            session_id: Session ID for passer creation.
            scope_tag: Scope tag for passer creation.

        Returns:
            Detected MCP type or None.
        """
        for mcp_type, passer_class in cls._passers.items():
            passer = passer_class(session_id, scope_tag)
            if passer.can_handle(raw_output):
                return mcp_type
        return None


def normalize(
    raw_output: Union[str, bytes, Dict[str, Any]],
    mcp_type: Optional[MCPType],
    session_id: str,
    scope_tag: str,
    created_by: str = "passer",
    **kwargs: Any,
) -> PasserResult:
    """
    Normalize MCP output using the appropriate passer.

    This is the main entry point for normalizing MCP outputs.

    Args:
        raw_output: Raw output from the MCP server.
        mcp_type: MCP type (will auto-detect if None).
        session_id: Current session ID.
        scope_tag: Scope tag for created objects.
        created_by: Creator identifier.
        **kwargs: Additional parameters for the passer.

    Returns:
        PasserResult containing normalized objects.
    """
    result = PasserResult()

    # Auto-detect MCP type if not provided
    if mcp_type is None:
        mcp_type = PasserRegistry.detect_type(raw_output, session_id, scope_tag)
        if mcp_type is None:
            result.add_error("Could not detect MCP type from output")
            return result

    # Get the passer
    passer_class = PasserRegistry.get(mcp_type)
    if passer_class is None:
        result.add_error(f"No passer registered for MCP type: {mcp_type.value}")
        return result

    # Create passer instance and normalize
    passer = passer_class(session_id, scope_tag, created_by)
    try:
        return passer.normalize(raw_output, **kwargs)
    except Exception as e:
        result.add_error(f"Passer failed: {str(e)}")
        logger.exception(f"Passer {mcp_type.value} failed")
        return result
