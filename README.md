# PyShield-SAST: Python Static Application Security Testing Tool

PyShield-SAST is a static analysis tool that parses Python source code into an Abstract Syntax Tree (AST) to identify security vulnerabilities. It features a modern, clean HTML report dashboard highlighting issues and recommended remediations.

## Features

- **AST-Based Vulnerability Scanning**: Tracks user-controlled values through local assignments, scanned-module imports, and instance methods before reporting an injection sink.
- **Offensive Security Rule Coverage**:
  - **SEC101**: Hardcoded secrets, API keys, and passwords.
  - **SEC102**: Weak cryptographic hashing (MD5, SHA1).
  - **SEC103**: Command Injection patterns (`subprocess` with `shell=True`, dangerous `os.system` calls).
  - **SEC104**: SQL Injection (dynamic string construction for SQL execution arguments).
  - **SEC105**: Cross-Site Scripting / XSS (use of Flask's dynamic `render_template_string` or raw HTML bypasses).
- **Interactive Report Dashboard**: Generates a responsive, CSS-styled HTML dashboard displaying statistics, code snippets, location mapping, and remediation steps.

## Installation

To install PyShield-SAST in development mode:

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
pyshield tests/vulnerable_app.py --html report.html

# Scan an entire directory recursively
pyshield tests --html report.html --json report.json
```

## Project Structure
- `pyshield/`
  - `rules/`
    - `__init__.py`: Rule exporter
    - `base.py`: Vulnerability & Rule abstractions
    - `hardcoded_secrets.py`: Rule SEC101
    - `weak_hash.py`: Rule SEC102
    - `command_injection.py`: Rule SEC103
    - `sql_injection.py`: Rule SEC104
    - `xss_risk.py`: Rule SEC105
  - `cli.py`: Console entry point & CLI parser
  - `scanner.py`: File traversal and AST parsing engine
  - `reporter.py`: HTML & CSS report rendering system
- `tests/`
  - `vulnerable_app.py`: Security baseline test suite
- `setup.py`: Packaging metadata
