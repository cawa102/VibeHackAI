"""
CLI module for PentestAgent.

Provides command-line interface for human interaction with the orchestrator.
"""

from .cli import CLI, CLIConfig
from .prompts import Prompts
from .display import Display
from .interactive_cli import InteractiveCLI, user_interaction_callback
from .report_generator import ReportGenerator

__all__ = [
    "CLI",
    "CLIConfig",
    "Prompts",
    "Display",
    "InteractiveCLI",
    "user_interaction_callback",
    "ReportGenerator",
]
