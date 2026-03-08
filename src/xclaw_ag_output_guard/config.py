"""
Configuration management for xclaw-ag-output-guard.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class Config:
    """Configuration for output guard."""
    
    # Detection thresholds
    block_threshold: float = 0.8
    warn_threshold: float = 0.5
    
    # Detector configuration
    exfiltration_guard_enabled: bool = True
    output_injection_enabled: bool = True
    
    # Action configuration
    auto_redact: bool = True
    redaction_marker: str = "[REDACTED]"
    
    # Logging configuration
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # Additional settings
    max_content_length: int = 100000
    allowed_destinations: list = field(default_factory=lambda: ["user", "memory"])
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if not 0 <= self.block_threshold <= 1:
            raise ValueError("block_threshold must be between 0 and 1")
        if not 0 <= self.warn_threshold <= 1:
            raise ValueError("warn_threshold must be between 0 and 1")
        if self.warn_threshold >= self.block_threshold:
            raise ValueError("warn_threshold must be less than block_threshold")
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        """Create configuration from dictionary."""
        # Filter only valid fields
        valid_fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid_fields)
    
    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load configuration from YAML file."""
        if not YAML_AVAILABLE:
            logging.warning("PyYAML not available, using default config")
            return cls()
        
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
            return cls.from_dict(data or {})
        except Exception as e:
            logging.error(f"Failed to load config from {path}: {e}")
            return cls()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'block_threshold': self.block_threshold,
            'warn_threshold': self.warn_threshold,
            'exfiltration_guard_enabled': self.exfiltration_guard_enabled,
            'output_injection_enabled': self.output_injection_enabled,
            'auto_redact': self.auto_redact,
            'redaction_marker': self.redaction_marker,
            'log_level': self.log_level,
            'log_file': self.log_file,
            'max_content_length': self.max_content_length,
            'allowed_destinations': self.allowed_destinations,
        }
