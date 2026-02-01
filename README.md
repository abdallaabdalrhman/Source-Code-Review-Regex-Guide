# Source-Code-Review-Regex-Guide

A comprehensive technical guide for performing security-focused source code reviews and leveraging regular expressions to automate vulnerability detection across modern web application codebases.

What This Guide Covers
SectionTopicsMethodologyBlack-box vs white-box analysis, 5-phase review workflow (recon → scan → review → classify → report)Vulnerability PatternsXSS, SQLi, path traversal, command injection, SSRF, CSRF, IDOR, XXE, deserialization, arbitrary redirection — with vulnerable & secure code examplesLanguage-Specific ReviewSecurity-critical APIs and input sources mapped for Java, ASP.NET, PHP, Perl, Python, JavaScript, Go, Ruby, C#, Swift, Kotlin, C/C++Platform ConfigurationSecurity-relevant settings in Java web.xml, ASP.NET Web.config, PHP php.ini, and Perl taint modeRegex for SecurityPattern cheat sheets targeting hardcoded secrets, injection vectors, and insecure configurations — with syntax reference and per-language usagePython ScannerStandalone CLI tool — recursive directory scanning, 20 detection rules across 4 severity levels, CWE mapping, colored output, JSON exportChecklist & Reporting22-item pre-review checklist, severity classification framework, and structured report templates


# Included Tool — scanner.py
A regex-based static analysis scanner written in Python.
bash# Scan a project directory
python scanner.py ./my_project

# Scan and export a structured JSON report
python scanner.py ./my_project --json report.json
Features:

Supports 16 file extensions: .py .js .ts .jsx .tsx .java .php .cs .go .rb .swift .kt .c .cpp .h .pl
Excludes node_modules, .git, venv, vendor, and other build directories automatically
Detection rules mapped to CWE identifiers
Severity levels: CRITICAL → HIGH → MEDIUM → LOW
Colored terminal output for quick triage
JSON export for CI/CD or further processing

Detection Categories:
SeverityWhat It CatchesCRITICALHardcoded passwords, API keys, AWS keys, private keys, JWT secretsHIGHSQL injection, command injection, eval/exec, unsafe deserialization, path traversal, dynamic file inclusionMEDIUMWeak hashes (MD5/SHA1), HTTP on sensitive endpoints, disabled SSL verification, secrets in logsLOWDebug mode enabled, commented-out credentials, security-related TODOs
Requirements

Python 3.7+
No external dependencies — uses only the standard library (re, json, pathlib, argparse)

License
Educational use only.
Author
0x2nac0nda — Cybersecurity Consultant
LinkedIn
