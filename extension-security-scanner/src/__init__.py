"""
Extension Security Scanner

A comprehensive security scanner for VS Code and Cursor extensions.
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .extension_scanner import ExtensionScanner
from .security_analyzer import SecurityAnalyzer
from .policy_engine import PolicyEngine
from .report_generator import ReportGenerator

__all__ = [
    "ExtensionScanner",
    "SecurityAnalyzer",
    "PolicyEngine",
    "ReportGenerator",
]