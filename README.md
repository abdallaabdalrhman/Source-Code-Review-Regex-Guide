# Source-Code-Review-Regex-Guide

# 🛡️ Source Code Review & Regex Guide

A comprehensive technical guide for performing security-focused source code reviews and leveraging regular expressions to automate vulnerability detection across modern web application codebases.

![Python](https://img.shields.io/badge/Language-Python%203.7%2B-3572A5?style=flat-square&logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen?style=flat-square)
![Severity](https://img.shields.io/badge/Severity%20Levels-4-blue?style=flat-square)
![Rules](https://img.shields.io/badge/Detection%20Rules-20%2B-orange?style=flat-square)
![Languages](https://img.shields.io/badge/Languages%20Supported-16-red?style=flat-square)
![License](https://img.shields.io/badge/License-Educational%20Use-gray?style=flat-square)

---

## 📖 Table of Contents

- [What This Guide Covers](#-what-this-guide-covers)
- [Included Tool — scanner.py](#-included-tool--scannerpy)
- [Usage](#-usage)
- [Output Example](#-output-example)
- [Detection Categories](#-detection-categories)
- [Supported File Extensions](#-supported-file-extensions)
- [Requirements](#-requirements)
- [License](#-license)
- [Author](#-author)

---

## 📘 What This Guide Covers

| # | Section | Topics |
|:---:|---------|--------|
| 01 | **Introduction** | What is source code review and why it matters |
| 02 | **Black-Box vs White-Box** | Testing strategies, when to combine both approaches |
| 03 | **Methodology** | 5-phase review workflow: `Recon → Scan → Review → Classify → Report` |
| 04 | **Vulnerability Patterns** | XSS, SQLi, Path Traversal, Command Injection, SSRF, CSRF, IDOR, XXE, Deserialization — with vulnerable & secure code examples |
| 05 | **Common Vulnerabilities** | Cross-language vulnerability breakdown |
| 06 | **Security Patterns** | Hardcoded secrets, insecure patterns, missing controls |
| 07 | **Language-Specific Review** | Security-critical APIs mapped for Java, ASP.NET, PHP, Perl, Python, JS, Go, Ruby, C#, Swift, Kotlin, C/C++ |
| 08 | **Dangerous APIs** | Platform-specific dangerous APIs for Java, ASP.NET, PHP, Perl |
| 09 | **Platform Configuration** | Security settings in `web.xml`, `Web.config`, `php.ini`, Perl taint mode |
| 10 | **Regex Fundamentals** | Core syntax, character classes, quantifiers, groups, anchors |
| 11 | **Regex by Language** | Per-language regex syntax reference |
| 12 | **Regex for Security** | Pattern cheat sheets targeting secrets, injection, and misconfigs |
| 13 | **Python Scanner** | Standalone CLI tool — the `scanner.py` included in this repo |
| 14 | **Vulnerability Checklist** | 22-item pre-review checklist |
| 15 | **Reporting** | Severity classification framework and structured report templates |
| 16 | **Regex Cheat Sheet** | Quick reference card |
| 17 | **VS Code Tips** | Extensions, shortcuts, search patterns, debugging tricks |
| 18 | **Key Takeaways** | Summary and next steps |

---

## 🔧 Included Tool — `scanner.py`

A **zero-dependency** regex-based static analysis scanner written in Python. Recursively scans your project directory and reports security vulnerabilities with CWE mapping and colored terminal output.

---

## 🚀 Usage

```bash
# Scan a project directory
python scanner.py ./my_project

# Scan and export a structured JSON report
python scanner.py ./my_project --json report.json
```

---

## 📊 Output Example

```
══════════════════════════════════════════════════════════════
   SOURCE CODE SECURITY SCANNER  —  0x2nac0nda
══════════════════════════════════════════════════════════════
  Target   : /home/user/my_project
  Started  : 2026-02-01 12:00:00
  Patterns : 20 rules across 4 severity levels

──────────────────────────────────────────────────────────────
  SCAN SUMMARY
──────────────────────────────────────────────────────────────
  Files scanned   : 47
  Total findings  : 6
    CRITICAL  : 1
    HIGH      : 2
    MEDIUM    : 2
    LOW       : 1
──────────────────────────────────────────────────────────────

  [CRITICAL]  Hardcoded Password
       CWE    : CWE-259
       File   : src/config/database.py
       Line   : 14
       Info   : Password hardcoded in source code.
       Code   : DB_PASSWORD = "admin1234"

  [HIGH]  SQL Injection
       CWE    : CWE-89
       File   : app/models/user.py
       Line   : 32
       Info   : Possible SQL injection via string concatenation.
       Code   : query = "SELECT * FROM users WHERE name=" + user_input

  [MEDIUM]  Weak Hash Algorithm
       CWE    : CWE-327
       File   : utils/hash.py
       Line   : 8
       Info   : Weak cryptographic hash algorithm in use.
       Code   : hashed = md5(password.encode()).hexdigest()
```

---

## 🎯 Detection Categories

| Severity | What It Catches | CWEs |
|:--------:|-----------------|------|
| 🔴 **CRITICAL** | Hardcoded passwords, API keys, AWS keys, private keys, JWT secrets | CWE-259, CWE-798 |
| 🟠 **HIGH** | SQL injection, command injection, eval/exec, unsafe deserialization, path traversal, dynamic file inclusion | CWE-89, CWE-78, CWE-94, CWE-502, CWE-22, CWE-98 |
| 🟡 **MEDIUM** | Weak hashes (MD5/SHA1), HTTP on sensitive endpoints, disabled SSL verification, secrets in logs | CWE-327, CWE-319, CWE-295, CWE-532 |
| 🟢 **LOW** | Debug mode enabled, commented-out credentials, security-related TODOs | CWE-94, CWE-798, CWE-120 |

---

## 📂 Supported File Extensions

```
.py    .js    .ts    .jsx   .tsx
.java  .php   .cs    .go    .rb
.swift .kt    .c     .cpp   .h    .pl
```

> ⚠️ Automatically excludes: `node_modules`, `.git`, `venv`, `__pycache__`, `vendor`, `dist`, `build`

---

## ⚙️ Requirements

| Requirement | Details |
|-------------|---------|
| **Python** | 3.7 or higher |
| **Dependencies** | Zero — uses only the standard library (`re`, `json`, `pathlib`, `argparse`) |
| **OS** | Windows, macOS, Linux |

---

## 📄 License

This project is for **educational use only**.

---

## 👤 Author

| | |
|:---|:---|
| **Name** | Abdalla Abdelrhman |
| **Handle** | 0x2nac0nda |
| **Title** | Cybersecurity Consultant |
| **LinkedIn** | [linkedin.com/in/0x2nac0nda](https://www.linkedin.com/in/0x2nac0nda/) |
