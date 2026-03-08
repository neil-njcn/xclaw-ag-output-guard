"""
Output guard interceptor for OpenClaw integration.

This module provides the interceptor that integrates with OpenClaw's
output processing pipeline to validate agent outputs.
"""

import logging
from typing import Any, Dict, Optional

from .config import Config
from .detector import OutputGuard, ValidationResult


class OutputGuardInterceptor:
    """
    Interceptor for OpenClaw output processing pipeline.
    
    This class integrates with OpenClaw to automatically validate
    all agent outputs before they are sent to users.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the interceptor.
        
        Args:
            config: Configuration object. If None, uses default.
        """
        self.config = config or Config()
        self.guard = OutputGuard(self.config)
        self.logger = logging.getLogger(__name__)
    
    def intercept(self, output: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Intercept and validate output.
        
        Args:
            output: The output content to validate
            context: Optional context information
        
        Returns:
            Dict with 'allowed', 'output', and 'result' keys
        """
        result = self.guard.validate(output, context)
        
        if result.action == "block":
            self.logger.warning(f"Output blocked: {result.reason}")
            return {
                'allowed': False,
                'output': self.guard.block_response(),
                'result': result.to_dict(),
            }
        elif result.action == "redact":
            self.logger.info(f"Output redacted: {result.reason}")
            return {
                'allowed': True,
                'output': result.redacted_content or output,
                'result': result.to_dict(),
            }
        else:
            return {
                'allowed': True,
                'output': output,
                'result': result.to_dict(),
            }
    
    def __call__(self, output: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        Make interceptor callable for direct use.
        
        Args:
            output: The output content
            context: Optional context
        
        Returns:
            The (possibly modified) output
        """
        result = self.intercept(output, context)
        return result['output']
