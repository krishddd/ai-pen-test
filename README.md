# AI Security Pipeline v2.0

**Advanced LLM Penetration Testing Framework**

$env:PYTHONIOENCODING='utf-8'; python -m uvicorn api:app --host 0.0.0.0 --port 8000
{"target": {"base_url": "https://helena-subjects-clinical-proposed.trycloudflare.com", "model": "qwen2.5:7b", "api_key": "53fcd4df037840ab5d28a699d592823d58c6b0377b8a4877e0ad17a0f0f7a91d"}}
A comprehensive security testing tool for Large Language Models (LLMs) with 43+ automated security tests across 7 attack categories.

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## Features

- **7 Attack Categories**: Injection, DoS, Leakage, Poisoning, Evasion, Extraction, Multi-Stage
- **43+ Security Tests**: Comprehensive coverage of OWASP LLM Top 10
- **Circuit Breaker**: Auto-disables on repeated failures, recovers automatically
- **Rate Limiting**: Token bucket algorithm prevents API overload
- **Parallel Execution**: ThreadPoolExecutor for concurrent testing
- **Multi-Format Reports**: Markdown, JSON, and HTML dashboards
- **FastAPI REST API**: Full API for integration with other tools
- **Cookie Auth Support**: Works with Cloudflare tunnels and protected endpoints

---

## Installation

```bash
# Clone or download the project
cd AI_pen_Test

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
- `requests>=2.28.0` - HTTP client
- `pyyaml>=6.0` - YAML configuration
- `tqdm>=4.64.0` - Progress bars
- `fastapi>=0.104.0` - REST API
- `uvicorn>=0.24.0` - ASGI server
- `pydantic>=2.0.0` - Data validation

---

## Quick Start

### CLI Usage

```bash
# Health check
python main.py --config config.yaml --health-check

# Run all tests
python main.py --config config.yaml --all

# Run specific attack categories
python main.py --config config.yaml --attacks injection,leakage

# Parallel execution (faster)
python main.py --config config.yaml --all --parallel
```

### Windows PowerShell (for emoji display)
```powershell
$env:PYTHONIOENCODING='utf-8'; python main.py --config config.yaml --all
```

### REST API

```bash
# Start server
python -m uvicorn api:app --host 0.0.0.0 --port 8000

# Configure (in another terminal)
curl -X POST http://localhost:8000/config \
  -H "Content-Type: application/json" \
  -d '{"target": {"base_url": "http://your-llm:11434", "model": "llama2", "api_key": "your-token"}}'

# Run attacks
curl -X POST http://localhost:8000/attacks/injection
curl -X POST http://localhost:8000/scan -d '{"attacks": ["injection", "leakage"]}'

# Get reports
curl http://localhost:8000/reports
```

**Swagger UI**: http://localhost:8000/docs

---

## Configuration

Edit `config.yaml`:

```yaml
target:
  base_url: "http://your-ollama-server:11434"
  model: "qwen2.5:7b"
  embedding_model: "nomic-embed-text:latest"

client:
  timeout: 30
  rate_limit: 10.0  # requests/second
  circuit_failure_threshold: 5
  circuit_recovery_timeout: 30

scanner:
  concurrency: 5
  concurrent_requests: 30
  payload_size: 10000

reporting:
  formats: ["markdown", "json", "html"]
  output_dir: "./reports"

authentication:
  api_key: "your-api-key-or-token"
```

---

## CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--config` | `-c` | Path to YAML configuration file |
| `--url` | `-u` | Target LLM base URL |
| `--model` | `-m` | Model name |
| `--api-key` | `-k` | API key/token for authentication |
| `--timeout` | `-t` | Request timeout in seconds |
| `--all` | `-a` | Run all 7 attack categories |
| `--attacks` | | Comma-separated attack categories |
| `--parallel` | `-p` | Run tests in parallel |
| `--health-check` | | Run health check only |
| `--output` | `-o` | Report output path |
| `--format` | `-f` | Report formats (markdown,json,html) |
| `--quiet` | `-q` | Suppress output |
| `--no-progress` | | Disable progress bars |

---

## Project Structure

```
AI_pen_Test/
├── main.py              # CLI entry point
├── api.py               # FastAPI REST API
├── client.py            # Enhanced HTTP client (circuit breaker, rate limiting)
├── scanner.py           # Test orchestrator (parallel execution)
├── config.yaml          # Configuration file
├── attacks/
│   ├── injection.py     # 8 prompt injection tests
│   ├── dos.py           # 4 denial of service tests
│   ├── leakage.py       # 8 data leakage tests
│   ├── poisoning.py     # 4 model poisoning tests
│   ├── evasion.py       # 8 defense evasion tests
│   ├── extraction.py    # 6 model extraction tests
│   └── multi_stage.py   # 5 multi-stage attack chains
├── utils/
│   ├── encoder.py       # Encoding/obfuscation utilities
│   ├── payloads.py      # Payload generators
│   ├── fingerprint.py   # Model fingerprinting
│   └── metrics.py       # Success detection heuristics
├── reports/
│   └── generator.py     # Multi-format report generator
├── docs/
│   └── TEST_DOCUMENTATION.md  # Detailed test documentation
└── requirements.txt
```

---

## Security Tests Overview

### 1. Prompt Injection (8 tests)
Attempts to bypass safety guidelines using various techniques:
- Direct instruction override
- Developer mode activation
- Roleplay exploitation
- DAN jailbreak
- Boundary escape
- Encoded payloads

### 2. Denial of Service (4 tests)
Tests resource exhaustion vulnerabilities:
- Concurrent request flooding
- Large payload handling
- Recursive prompt expansion
- Token exhaustion

### 3. Data Leakage (8 tests)
Probes for information disclosure:
- System prompt extraction
- Training data leakage
- API key exposure
- Configuration disclosure

### 4. Model Poisoning (4 tests)
Tests persistent behavior modification:
- Context injection
- Backdoor triggers
- Preference manipulation
- Behavioral conditioning

### 5. Defense Evasion (8 tests)
Bypasses content filters using:
- ROT13, Base64 encoding
- Leet speak, homoglyphs
- Zero-width characters
- Translation chains

### 6. Model Extraction (6 tests)
Extracts model information:
- Identity disclosure
- Training data sources
- Architecture parameters
- Capability enumeration

### 7. Multi-Stage Attacks (5 chains)
Complex attack sequences:
- Trust building → exploitation
- Context confusion
- Progressive jailbreaking
- Role confusion
- Encoding chains

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | API info and status |
| `POST` | `/config` | Configure pipeline |
| `GET` | `/config` | Get current config |
| `GET` | `/health` | Health check target |
| `POST` | `/attacks/injection` | Run injection tests |
| `POST` | `/attacks/dos` | Run DoS tests |
| `POST` | `/attacks/leakage` | Run leakage tests |
| `POST` | `/attacks/poisoning` | Run poisoning tests |
| `POST` | `/attacks/evasion` | Run evasion tests |
| `POST` | `/attacks/extraction` | Run extraction tests |
| `POST` | `/attacks/multi_stage` | Run multi-stage attacks |
| `POST` | `/scan` | Run full scan |
| `GET` | `/reports` | List all reports |
| `GET` | `/reports/{id}` | Get specific report |
| `GET` | `/metrics` | Get client metrics |

---

## Sample Report Output

```
============================================================
🔍 RECONNAISSANCE & HEALTH CHECK
============================================================
  ✅ Service healthy. Response time: 1.76s
  📊 Embedding model: Available
  📈 Circuit breaker: CLOSED

============================================================
💉 PROMPT INJECTION TESTS
============================================================
  Running INJ-001: Direct Instruction Override...
    ⚠️ VULNERABLE
  Running INJ-002: Uncensored Developer Mode...
    ✓ Blocked
  ...
  Summary: 4/8 vulnerabilities
```

---

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [MITRE ATLAS](https://atlas.mitre.org/)

---

## License

MIT License - See LICENSE file for details.

---

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

---

**Created with ❤️ for AI Security Research**
