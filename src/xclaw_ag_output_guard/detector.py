"""
Output detection logic using xclaw-agentguard framework.

This module provides output validation to detect credential leaks,
PII exposure, and harmful content.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    from xclaw_agentguard import (
        ExfiltrationGuard,
        OutputInjectionDetector,
    )
    XCLAW_AGENTGUARD_AVAILABLE = True
except ImportError:
    XCLAW_AGENTGUARD_AVAILABLE = False
    class ExfiltrationGuard:
        def detect(self, text: str) -> Dict[str, Any]:
            return {"detected": False, "confidence": 0.0, "patterns": []}
    class OutputInjectionDetector:
        def detect(self, text: str) -> Dict[str, Any]:
            return {"detected": False, "confidence": 0.0, "patterns": []}

from .config import Config


@dataclass
class ValidationResult:
    """Result of output analysis."""
    
    is_safe: bool = True
    detected: bool = False
    confidence: float = 0.0
    risk_type: Optional[str] = None
    action: str = "allow"
    reason: Optional[str] = None
    redacted_content: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_safe': self.is_safe,
            'detected': self.detected,
            'confidence': self.confidence,
            'risk_type': self.risk_type,
            'action': self.action,
            'reason': self.reason,
            'redacted_content': self.redacted_content,
            'details': self.details,
        }


class OutputGuard:
    """Main class for output validation and sanitization."""
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.logger = logging.getLogger(__name__)
        self._detectors: Dict[str, Any] = {}
        self._init_detectors()
    
    def _init_detectors(self) -> None:
        """Initialize enabled detectors."""
        if not XCLAW_AGENTGUARD_AVAILABLE:
            self.logger.warning("xclaw-agentguard not available, using fallback detectors")
            return
        
        if self.config.exfiltration_guard_enabled:
            self._detectors['exfiltration'] = ExfiltrationGuard()
        if self.config.output_injection_enabled:
            self._detectors['output_injection'] = OutputInjectionDetector()
    
    def validate(self, content: str, context: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """
        Validate output content for risks.
        
        Args:
            content: Output text to validate
            context: Optional context (output_type, destination, tool_name)
        
        Returns:
            ValidationResult with risk assessment
        """
        if not content or not isinstance(content, str):
            return ValidationResult()
        
        result = ValidationResult()
        max_confidence = 0.0
        detected_risks = []
        
        # Run all enabled detectors
        for name, detector in self._detectors.items():
            try:
                detection = detector.detect(content)
                if detection.get('detected', False):
                    confidence = detection.get('confidence', 0.0)
                    max_confidence = max(max_confidence, confidence)
                    detected_risks.append({
                        'detector': name,
                        'confidence': confidence,
                        'patterns': detection.get('patterns', []),
                    })
            except Exception as e:
                self.logger.error(f"Detector {name} failed: {e}")
        
        # Determine action based on findings
        if detected_risks:
            result.detected = True
            result.confidence = max_confidence
            result.risk_type = detected_risks[0]['detector']
            result.details = {'risks': detected_risks}
            
            if max_confidence >= self.config.block_threshold:
                result.action = "block"
                result.is_safe = False
                result.reason = f"High-risk content detected (confidence: {max_confidence:.2f})"
            elif max_confidence >= self.config.warn_threshold:
                result.action = "redact"
                result.is_safe = False
                result.reason = f"Sensitive content detected (confidence: {max_confidence:.2f})"
                if self.config.auto_redact:
                    result.redacted_content = self._redact(content, detected_risks)
            else:
                result.action = "log"
                result.reason = f"Low-risk content flagged (confidence: {max_confidence:.2f})"
        
        return result
    
    def _redact(self, content: str, risks: List[Dict]) -> str:
        """Redact sensitive content."""
        # Simple redaction - replace detected patterns
        redacted = content
        for risk in risks:
            for pattern in risk.get('patterns', []):
                redacted = redacted.replace(pattern, '[REDACTED]')
        return redacted
    
    def block_response(self) -> str:
        """Get block response message."""
        return "This output contains sensitive information and cannot be displayed."
