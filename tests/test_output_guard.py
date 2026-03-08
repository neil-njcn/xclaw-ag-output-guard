"""
Tests for xclaw-ag-output-guard
"""

import pytest
from xclaw_ag_output_guard import OutputGuard, ValidationResult, Config


def test_config_defaults():
    """Test default configuration"""
    config = Config()
    assert config.block_threshold == 0.8
    assert config.warn_threshold == 0.5
    assert config.auto_redact is True


def test_guard_initialization():
    """Test guard initialization"""
    guard = OutputGuard()
    assert guard is not None


def test_validate_safe_content():
    """Test validation of safe content"""
    guard = OutputGuard()
    result = guard.validate("Hello, this is a normal response.")
    assert isinstance(result, ValidationResult)


def test_config_validation():
    """Test configuration validation"""
    with pytest.raises(ValueError):
        Config(block_threshold=1.5)
    
    with pytest.raises(ValueError):
        Config(warn_threshold=0.9, block_threshold=0.5)


def test_config_from_dict():
    """Test loading config from dict"""
    config = Config.from_dict({
        'block_threshold': 0.9,
        'auto_redact': False,
    })
    assert config.block_threshold == 0.9
    assert config.auto_redact is False


def test_block_response():
    """Test block response message"""
    guard = OutputGuard()
    response = guard.block_response()
    assert "sensitive information" in response.lower()
