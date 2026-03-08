# xclaw-ag-output-guard

> **Framework:** [XClaw AgentGuard v2.3.1](https://github.com/neil-njcn/xclaw-agentguard-framework)

Output validation and sanitization for OpenClaw agents. Prevents credential leaks, PII exposure, and harmful content.

## Installation

```bash
openclaw skills install https://github.com/neil-njcn/xclaw-ag-output-guard.git
```

## Usage

```python
from xclaw_ag_output_guard import OutputGuard

guard = OutputGuard()
result = guard.validate("output content here")

if result.is_safe:
    send_output()
elif result.action == "block":
    block_output(result.reason)
elif result.action == "redact":
    send_redacted(result.redacted_content)
```

## Core Principle

> **Every output is a liability until validated.**

Before sending ANY response, validate through output-guard.

## Detectors

- **ExfiltrationGuard**: API keys, passwords, connection strings
- **OutputInjectionDetector**: Malicious content, phishing attempts

## Response Protocol

| Risk Level | Action | Response |
|------------|--------|----------|
| **Critical** | Block | Don't send; alert operator |
| **High** | Redact | Send redacted version |
| **Medium** | Warn | Send with warning |
| **Low** | Log | Allow, log for analysis |

## Integration Note

`openclaw.register_interceptor()` is not implemented. Use manual `guard.validate()` as shown above.

## License

MIT License
