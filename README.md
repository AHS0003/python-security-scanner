# 🔐 Python SAST Agent

Autonomous static application security testing (SAST) agent for Python files. Detects common application vulnerabilities through pattern-based code analysis, generates remediation advice, and exposes its scanning engine via a REST API — designed with the same logic as a security-analysis assistant agent.

## Features

- **CLI scan** of a single file or an entire Python directory (recursive)
- **6 detection rules** covering the most common OWASP categories:

| Rule | Severity | Category |
|---|---|---|
| `eval()` | HIGH | Code injection |
| `exec()` | HIGH | Code injection |
| `os.system()` | HIGH | System execution |
| `subprocess.*` | MEDIUM | System execution |
| Hardcoded password | CRITICAL | Exposed secrets |
| Hardcoded API key | CRITICAL | Exposed secrets |

- **Remediation advice** generated for every detected vulnerability
- **Colored report** sorted by severity (CRITICAL → HIGH → MEDIUM → LOW) with a numeric summary
- **JSON output** (`--format json`) for CI/CD pipeline integration
- **REST API** (Flask) exposing the scan engine through 4 endpoints

## Installation

```bash
git clone https://github.com/AHS0003/python-security-scanner.git
cd python-security-scanner
pip install -r requirements.txt
```

## Usage — CLI

Scan a single file:
```bash
python security_scanner.py sample_vulnerable.py
```

Scan an entire directory:
```bash
python security_scanner.py .
```

JSON output (for CI/CD pipelines):
```bash
python security_scanner.py sample_vulnerable.py --format json
```

## Usage — REST API

Start the server:
```bash
python api.py
```
The API starts on `http://localhost:5000`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Agent health check |
| `GET` | `/rules` | List of active detection rules |
| `POST` | `/scan/file` | Scan an uploaded `.py` file |
| `POST` | `/scan/code` | Scan code submitted as JSON |

Examples:
```bash
curl http://localhost:5000/health

curl -X POST http://localhost:5000/scan/file \
     -F "file=@sample_vulnerable.py"

curl -X POST http://localhost:5000/scan/code \
     -H "Content-Type: application/json" \
     -d '{"code": "password = \"admin123\"\neval(input())"}'
```

## Project structure

```
.
├── security_scanner.py    # Scan engine + CLI
├── api.py                 # REST API (Flask)
├── sample_vulnerable.py   # Test file (intentional vulnerabilities)
├── requirements.txt
└── .gitignore
```

## Tech stack

Python · Flask · Regular expressions · REST API · Autonomous agent architecture

## Skills demonstrated

- Static application security testing (SAST) and vulnerability pattern recognition
- Designing a stateless REST API
- OWASP awareness (code injection, system execution, secret exposure)
- DevSecOps best practices (CI/CD integration via JSON output)
