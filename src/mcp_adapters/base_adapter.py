"""
Base MCP Adapter for PentestAgent.

Provides common functionality for all MCP adapters.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class MCPToolType(str, Enum):
    """Types of MCP tools."""
    SHODAN = "shodan"
    OSINT = "osint"
    NMAP = "nmap"
    BURP = "burp"
    GITHUB = "github"
    SNYK = "snyk"
    MSF = "metasploit"
    KALI = "kali"


class MCPError(Exception):
    """Exception for MCP-related errors."""

    def __init__(
        self,
        message: str,
        tool: str,
        operation: str,
        details: Optional[Dict[str, Any]] = None,
        retryable: bool = False,
    ):
        super().__init__(message)
        self.message = message
        self.tool = tool
        self.operation = operation
        self.details = details or {}
        self.retryable = retryable

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "error": self.message,
            "tool": self.tool,
            "operation": self.operation,
            "details": self.details,
            "retryable": self.retryable,
        }


@dataclass
class MCPResult:
    """
    Result from an MCP tool invocation.

    Contains the raw result and metadata.
    """
    tool: str
    operation: str
    success: bool
    result_id: str = dataclass_field(default_factory=lambda: f"mcp-{uuid.uuid4().hex[:8]}")
    data: Optional[Dict[str, Any]] = None
    raw_output: Optional[str] = None
    error: Optional[str] = None
    timestamp: datetime = dataclass_field(default_factory=datetime.utcnow)
    duration_ms: Optional[int] = None
    metadata: Dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "result_id": self.result_id,
            "tool": self.tool,
            "operation": self.operation,
            "success": self.success,
            "data": self.data,
            "raw_output": self.raw_output,
            "error": self.error,
            "timestamp": self.timestamp.isoformat() + "Z",
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }

    def to_evidence(self) -> Dict[str, Any]:
        """Convert to evidence format."""
        return {
            "evidence_id": self.result_id,
            "source": self.tool,
            "source_type": "mcp_tool",
            "operation": self.operation,
            "timestamp": self.timestamp.isoformat() + "Z",
            "data": self.data,
            "raw_output": self.raw_output,
            "metadata": self.metadata,
        }


class BaseMCPAdapter(ABC):
    """
    Abstract base class for MCP adapters.

    Provides common functionality for:
    - Tool invocation
    - Result handling
    - Error handling
    - Evidence generation
    """

    def __init__(
        self,
        tool_type: MCPToolType,
        timeout_seconds: int = 60,
        max_retries: int = 2,
    ):
        """
        Initialize adapter.

        Args:
            tool_type: Type of MCP tool.
            timeout_seconds: Timeout for operations.
            max_retries: Maximum retry attempts.
        """
        self.tool_type = tool_type
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._last_result: Optional[MCPResult] = None

    @property
    def tool_name(self) -> str:
        """Get tool name."""
        return self.tool_type.value

    @abstractmethod
    def _invoke_tool(
        self,
        operation: str,
        params: Dict[str, Any],
    ) -> MCPResult:
        """
        Invoke the MCP tool.

        Args:
            operation: Operation to perform.
            params: Parameters for the operation.

        Returns:
            MCPResult with the result.
        """
        pass

    def invoke(
        self,
        operation: str,
        params: Dict[str, Any],
        retry: bool = True,
    ) -> MCPResult:
        """
        Invoke the MCP tool with optional retry.

        Args:
            operation: Operation to perform.
            params: Parameters for the operation.
            retry: Whether to retry on failure.

        Returns:
            MCPResult with the result.
        """
        start_time = datetime.utcnow()
        last_error: Optional[Exception] = None
        attempts = self.max_retries + 1 if retry else 1

        for attempt in range(attempts):
            try:
                result = self._invoke_tool(operation, params)
                result.duration_ms = int(
                    (datetime.utcnow() - start_time).total_seconds() * 1000
                )
                self._last_result = result
                return result

            except MCPError as e:
                last_error = e
                if not e.retryable or attempt >= attempts - 1:
                    break
                # Wait before retry (exponential backoff)
                import time
                time.sleep(2 ** attempt)

            except Exception as e:
                last_error = e
                if attempt >= attempts - 1:
                    break

        # All retries failed
        duration_ms = int(
            (datetime.utcnow() - start_time).total_seconds() * 1000
        )
        error_msg = str(last_error) if last_error else "Unknown error"

        result = MCPResult(
            tool=self.tool_name,
            operation=operation,
            success=False,
            error=error_msg,
            duration_ms=duration_ms,
            metadata={"params": params, "attempts": attempts},
        )
        self._last_result = result
        return result

    def get_last_result(self) -> Optional[MCPResult]:
        """Get the last invocation result."""
        return self._last_result

    def is_available(self) -> bool:
        """
        Check if the MCP tool is available.

        Override in subclasses for specific checks.
        """
        return True

    @abstractmethod
    def get_supported_operations(self) -> List[str]:
        """Get list of supported operations."""
        pass
