"""
Output detection logic using xclaw-agentguard framework.

This module provides output validation to detect credential leaks,
PII exposure, and harmful content.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

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
    
    # URL patterns for phishing detection - checks both domain and path
    PHISHING_URL_PATTERNS: List[Tuple[str, str]] = [
        # Domain-based phishing keywords
        (r'https?://[\w\.-]*phish[\w\.-]*\.(?:com|org|net|io|co)', 'phishing_domain'),
        (r'https?://[\w\.-]*fake[\w\.-]*\.(?:com|org|net|io|co)', 'fake_domain'),
        (r'https?://[\w\.-]*scam[\w\.-]*\.(?:com|org|net|io|co)', 'scam_domain'),
        (r'https?://[\w\.-]*malicious[\w\.-]*\.(?:com|org|net|io|co)', 'malicious_domain'),
        # Path-based phishing keywords
        (r'https?://[\w\.-]+\.(?:com|org|net|io|co)/\S*phish', 'phishing_path'),
        (r'https?://[\w\.-]+\.(?:com|org|net|io|co)/\S*fake', 'fake_path'),
        (r'https?://[\w\.-]+\.(?:com|org|net|io|co)/\S*scam', 'scam_path'),
    ]
    
    # Sensitive data patterns for credential leak detection
    SENSITIVE_PATTERNS: List[Tuple[str, str]] = [
        (r'password\s*[:=\s]\s*\S+', 'password'),
        (r'api[_-]?key\s*[:=\s]\s*\S+', 'api_key'),
        (r'sk-[a-zA-Z0-9]{20,}', 'openai_key'),
        (r'private[_-]?key\s*[:=\s]\s*\S+', 'private_key'),
        (r'token\s*[:=\s]\s*[a-zA-Z0-9_-]{20,}', 'token'),
    ]
    
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
        
        # Run local pattern detection for phishing URLs and sensitive data
        local_detection = self._detect_local_patterns(content)
        if local_detection['detected']:
            max_confidence = max(max_confidence, local_detection['confidence'])
            detected_risks.append({
                'detector': local_detection['type'],
                'confidence': local_detection['confidence'],
                'patterns': local_detection['patterns'],
            })
        
        # Run all enabled detectors from xclaw-agentguard
        for name, detector in self._detectors.items():
            try:
                detection = detector.detect(content)

                # Handle DetectionResult object (from xclaw-agentguard-framework v2.3.1+)
                # or dict (legacy compatibility)
                if hasattr(detection, 'detected'):
                    # DetectionResult object
                    is_detected = detection.detected
                    confidence = getattr(detection, 'confidence', 0.0)

                    # Extract patterns from DetectionEvidence
                    evidence = getattr(detection, 'evidence', None)
                    if evidence and hasattr(evidence, 'matched_patterns'):
                        patterns = evidence.matched_patterns
                    else:
                        patterns = []
                else:
                    # Legacy dict format
                    is_detected = detection.get('detected', False)
                    confidence = detection.get('confidence', 0.0)
                    patterns = detection.get('patterns', [])

                if is_detected:
                    max_confidence = max(max_confidence, confidence)
                    detected_risks.append({
                        'detector': name,
                        'confidence': confidence,
                        'patterns': patterns,
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
    
    def _detect_local_patterns(self, content: str) -> Dict[str, Any]:
        """
        Detect phishing URLs and sensitive data using local patterns.
        
        Args:
            content: Text content to analyze
            
        Returns:
            Dictionary with detection results
        """
        detected_patterns = []
        
        # Check for phishing URLs
        for pattern, ptype in self.PHISHING_URL_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                detected_patterns.append({
                    'type': ptype,
                    'match': match.group(0),
                    'pattern': pattern,
                })
        
        # Check for sensitive data
        for pattern, ptype in self.SENSITIVE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                detected_patterns.append({
                    'type': ptype,
                    'match': match.group(0),
                    'pattern': pattern,
                })
        
        if detected_patterns:
            # Determine confidence based on pattern types
            phishing_patterns = [p for p in detected_patterns if 'phish' in p['type'] or 'fake' in p['type'] or 'scam' in p['type']]
            sensitive_patterns = [p for p in detected_patterns if p['type'] in ['password', 'api_key', 'openai_key', 'private_key', 'token']]
            
            if phishing_patterns and sensitive_patterns:
                confidence = 0.95  # Both phishing and sensitive data - very high risk
                risk_type = 'combined_threat'
            elif phishing_patterns:
                confidence = 0.85  # Phishing URLs - high risk
                risk_type = 'phishing_url'
            else:
                confidence = 0.8   # Sensitive data - high risk
                risk_type = 'sensitive_data'
            
            return {
                'detected': True,
                'confidence': confidence,
                'type': risk_type,
                'patterns': [p['match'] for p in detected_patterns],
                'details': detected_patterns,
            }
        
        return {
            'detected': False,
            'confidence': 0.0,
            'type': None,
            'patterns': [],
            'details': [],
        }
    
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
