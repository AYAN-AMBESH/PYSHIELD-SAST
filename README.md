# SaPyScan: Python Static Application Security Testing Tool

SaPyScan is a static analysis tool that parses Python source code into an Abstract Syntax Tree (AST) to identify security vulnerabilities. It includes a modern HTML report dashboard with issue details and remediation guidance.

## Features

- **AST-Based Vulnerability Scanning**: Tracks user-controlled values through local assignments, scanned-module imports, and instance methods before reporting an injection sink.
- **Security Rule Coverage**:
  - Hardcoded secrets and credentials
  - Weak cryptographic hashes and ciphers
  - Command injection, SQL injection, and XSS risk patterns
  - Insecure deserialization and SSL/TLS misconfiguration
  - SSRF risk, path traversal risk, weak random usage, and dangerous eval usage
- **Interactive Report Dashboard**: Generates a responsive, CSS-styled HTML dashboard displaying statistics, code snippets, location mapping, and remediation steps.

## Installation

Install SaPyScan in development mode:

```bash
# Install package
pip install -e .

# Install development dependencies (pytest, ruff, etc.)
pip install -e ".[dev]"
# Or:
pip install -r requirements-dev.txt
```

## Running Tests

Verify the scanner works correctly using pytest:

```bash
pytest
```

## Usage

### Scan a file or directory:
```bash
# Scan a single file and generate report.html
sapyscan tests/vulnerable_app.py --html report.html

# Scan an entire directory recursively
sapyscan tests --html report.html --json report.json
```

## Project Structure
- `sapyscan/`: Main package
  - `cli.py`: CLI entry point and argument parsing
  - `scanner.py`: File traversal and AST parsing engine
  - `reporter.py`: HTML report rendering
  - `rules/`: Security rule implementations
    - `hardcoded_secrets.py`
    - `weak_hash.py`
    - `weak_cipher.py`
    - `command_injection.py`
    - `sql_injection.py`
    - `xss_risk.py`
    - `dangerous_eval.py`
    - `insecure_deserialization.py`
    - `insecure_ssl.py`
    - `ssrf.py`
    - `path_traversal.py`
    - `weak_random.py`
    - `assert_check.py`
    - `flask_debug.py`
- `tests/`: Unit tests and vulnerable sample application
- `pyproject.toml`: Project metadata and console script configuration
