# xclaw-ag-output-guard

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Output validation and sanitization for OpenClaw agents. Prevents credential leaks, PII exposure, and harmful content.
>
> **Framework:** [XClaw AgentGuard v2.3.1](https://github.com/neil-njcn/xclaw-agentguard-framework)

## 🛡️ Overview

`xclaw-ag-output-guard` validates AI-generated outputs and tool results before they reach users or external systems. It ensures sensitive data doesn't leak and content meets safety standards.

### Key Features

- 🔐 **Credential Leak Detection** - API keys, passwords, private keys, connection strings
- 👤 **PII Protection** - Emails, phone numbers, SSNs, credit cards
- 📁 **Path Disclosure Prevention** - System paths, user directories
- 🎯 **Hallucination Markers** - Overconfident claims, unverified statements
- ✂️ **Auto-redaction** - Automatically sanitize sensitive content

## 📦 Installation

### Via OpenClaw CLI (Recommended)

**Install from GitHub:**
```bash
openclaw skills install https://github.com/neil-njcn/xclaw-ag-output-guard.git
```

### From Source

```bash
git clone https://github.com/neil-njcn/xclaw-ag-output-guard.git
cd xclaw-ag-output-guard

# Install in editable mode with virtual environment
python -m venv venv
source venv/bin/activate
pip install -e .
```

### Via pip

```bash
# Install in user environment
pip install --user xclaw-ag-output-guard

# Or use virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install xclaw-ag-output-guard
```

## 🚀 Quick Start

After installation, the skill is ready to use. Import and use directly:

```python
from xclaw_ag_output_guard import OutputGuard

# Initialize with default configuration
guard = OutputGuard()

# Validate output
result = guard.validate("Contact me at user@example.com")
if result.is_safe:
    print("✅ Output is safe")
else:
    print(f"⚠️ Risk detected: {result.risk_type}")
    print(f"Safe version: {result.redacted_content}")
```

> **Note on Hook Integration:** Automatic hook integration is an advanced feature. Currently, OpenClaw does not provide hook interception points, so users need to manually integrate the guard into their workflow (as shown above).

## ⚙️ Configuration

Create a configuration file at `config/xclaw-ag-output-guard.yaml`:

```yaml
# Detection threshold (0.0 - 1.0)
block_threshold: 0.8
warn_threshold: 0.5

# Detector configuration
exfiltration_guard_enabled: true
output_injection_enabled: true

# Action configuration
auto_redact: true
redaction_marker: "[REDACTED]"

# Logging configuration
logging:
  level: INFO
  file: logs/output-guard.log
```

## 📖 Usage Examples

### Basic Protection

```python
from xclaw_ag_output_guard import OutputGuard

guard = OutputGuard()

# Safe output
result = guard.validate("Hello, how can I help you today?")
print(result.is_safe)  # True

# Output with PII
result = guard.validate("Contact me at john@example.com")
print(result.is_safe)   # False
print(result.action)    # "redact"
```

### Custom Configuration

```python
from xclaw_ag_output_guard import OutputGuard, Config

config = Config(
    block_threshold=0.9,
    auto_redact=True
)

guard = OutputGuard(config)
```

### OpenClaw Integration

> **Note:** `openclaw.register_interceptor()` is not currently implemented in OpenClaw. The example below shows the intended API for future integration:

```python
from xclaw_ag_output_guard.interceptor import OutputGuardInterceptor

# This API is planned but not yet available:
# interceptor = OutputGuardInterceptor()
# openclaw.register_interceptor("agent_output", interceptor)

# For now, use manual integration as shown in Basic Protection
```

## 🧪 Testing

```bash
# Run all tests
pytest tests/

# Run with coverage report
pytest tests/ --cov=xclaw_ag_output_guard --cov-report=html
```

## 🔒 Security

- **Threshold Tuning**: Adjust based on your security requirements
- **Regular Updates**: Keep detector patterns updated
- **Monitoring**: Review logs regularly
- **Defense in Depth**: Use as part of comprehensive security strategy

## 🤝 Contributing

We welcome contributions!

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Issue Tracker**: https://github.com/neil-njcn/xclaw-ag-output-guard/issues

## 💬 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/neil-njcn/xclaw-ag-output-guard/issues)

---

<p align="center">
  Made with ❤️ by KyleChen & Neil
</p>
