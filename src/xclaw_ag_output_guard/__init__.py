"""
xclaw-ag-output-guard: Output validation and sanitization for OpenClaw agents.

This package provides output protection to prevent credential leaks,
PII exposure, and harmful content in agent outputs.
"""

from .config import Config
from .detector import OutputGuard, ValidationResult
from .interceptor import OutputGuardInterceptor

__version__ = "1.0.0"
__author__ = "xclaw"
__email__ = "dev@xclaw.dev"

__all__ = [
    "Config",
    "OutputGuard",
    "ValidationResult",
    "OutputGuardInterceptor",
]


class OutputGuardSkill:
    """
    OpenClaw skill entry point for xclaw-ag-output-guard.
    
    This class provides the standard OpenClaw skill interface for
    registering and configuring the output guard.
    """
    
    name = "xclaw-ag-output-guard"
    version = __version__
    description = "Output validation and sanitization for OpenClaw agents"
    
    def __init__(self, config: dict = None):
        from .config import Config
        from .interceptor import OutputGuardInterceptor
        
        if config:
            self.config = Config.from_dict(config)
        else:
            self.config = Config()
        
        self.interceptor = OutputGuardInterceptor(self.config)
    
    def register(self, openclaw_app):
        """Register the skill with an OpenClaw application."""
        openclaw_app.register_interceptor("agent_output", self.interceptor)
    
    def get_interceptor(self):
        """Get the output guard interceptor for manual registration."""
        return self.interceptor
