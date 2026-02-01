#!/usr/bin/env python3
"""
============================================================
  Advanced Source Code Security Scanner
  Author  : 0x2nac0nda
  Version : 1.0
  License : Educational Use Only
============================================================
  Scans source code directories for security vulnerabilities
  using regex-based pattern matching. Supports 16 languages,
  multi-severity detection with CWE mapping, colored terminal
  output, and JSON export.

  Usage:
      python scanner.py ./project
      python scanner.py ./project --json report.json
============================================================
"""

import re
import os
import sys
import json
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path


# ─────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────

SUPPORTED_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx',
    '.java', '.php', '.cs', '.go',
    '.rb', '.swift', '.kt',
    '.c', '.cpp', '.h', '.pl'
}

EXCLUDED_DIRS = {
    'node_modules', '.git', 'venv', '__pycache__',
    '.env', 'dist', 'build', 'vendor',
    '.idea', '.vscode', 'bower_components'
}


# ─────────────────────────────────────────────────────────
#  VULNERABILITY PATTERNS  (Severity → Name → {regex, desc, cwe})
# ─────────────────────────────────────────────────────────

PATTERNS = {

    # ── CRITICAL ────────────────────────────────────────
    'CRITICAL': {
        'Hardcoded Password': {
            'regex': r'(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{3,}["\']',
            'desc' : 'Password hardcoded in source code.',
            'cwe'  : 'CWE-259'
        },
        'Hardcoded API Key': {
            'regex': r'(api[_-]?key|apikey|api_secret)\s*[:=]\s*["\'][A-Za-z0-9\-_]{10,}["\']',
            'desc' : 'API key or secret exposed in source.',
            'cwe'  : 'CWE-798'
        },
        'AWS Access Key': {
            'regex': r'AKIA[0-9A-Z]{16}',
            'desc' : 'AWS Access Key ID detected.',
            'cwe'  : 'CWE-798'
        },
        'Private Key Exposed': {
            'regex': r'-----BEGIN\s*(RSA\s+|EC\s+)?PRIVATE\s+KEY-----',
            'desc' : 'Private key found in source code.',
            'cwe'  : 'CWE-798'
        },
        'JWT Secret Hardcoded': {
            'regex': r'(jwt|token).*(secret|key)\s*[:=]\s*["\'][^"\']{8,}["\']',
            'desc' : 'JWT secret or signing key is hardcoded.',
            'cwe'  : 'CWE-798'
        },
    },

    # ── HIGH ─────────────────────────────────────────────
    'HIGH': {
        'SQL Injection': {
            'regex': r'(SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+\s*\w+',
            'desc' : 'Possible SQL injection via string concatenation.',
            'cwe'  : 'CWE-89'
        },
        'Command Injection': {
            'regex': r'(os\.system|subprocess\.call|exec|shell_exec|popen)\s*\(',
            'desc' : 'Dangerous OS command execution call detected.',
            'cwe'  : 'CWE-78'
        },
        'Dynamic Code Execution': {
            'regex': r'\b(eval|exec|Function)\s*\(',
            'desc' : 'Dynamic code evaluation with eval/exec/Function.',
            'cwe'  : 'CWE-94'
        },
        'Insecure Deserialization': {
            'regex': r'(pickle\.loads|unserialize|ObjectInputStream|Marshal\.load)',
            'desc' : 'Unsafe deserialization of potentially untrusted data.',
            'cwe'  : 'CWE-502'
        },
        'Path Traversal': {
            'regex': r'(\.\./|\.\.\\)',
            'desc' : 'Path traversal sequence detected.',
            'cwe'  : 'CWE-22'
        },
        'Dynamic File Inclusion': {
            'regex': r'(require|include)(_once)?\s*\(\s*\$',
            'desc' : 'Dynamic file inclusion with variable (LFI/RFI risk).',
            'cwe'  : 'CWE-98'
        },
    },

    # ── MEDIUM ───────────────────────────────────────────
    'MEDIUM': {
        'Weak Hash Algorithm': {
            'regex': r'\b(md5|sha1)\s*\(',
            'desc' : 'Weak cryptographic hash algorithm in use.',
            'cwe'  : 'CWE-327'
        },
        'HTTP Not HTTPS': {
            'regex': r'http://[^\s"\'<>]+((api|login|auth|pay|admin))',
            'desc' : 'Insecure HTTP used for a sensitive endpoint.',
            'cwe'  : 'CWE-319'
        },
        'SSL Verification Disabled': {
            'regex': r'(verify\s*=\s*False|rejectUnauthorized.*false)',
            'desc' : 'SSL/TLS certificate verification is disabled.',
            'cwe'  : 'CWE-295'
        },
        'Sensitive Data in Logs': {
            'regex': r'(print|log|console)\S*\(.*\b(password|secret|token|api_key)\b',
            'desc' : 'Possible sensitive data being written to logs.',
            'cwe'  : 'CWE-532'
        },
    },

    # ── LOW ──────────────────────────────────────────────
    'LOW': {
        'Debug Mode Enabled': {
            'regex': r'(DEBUG|debug)\s*[:=]\s*(true|True|TRUE|1)',
            'desc' : 'Debug mode is enabled in configuration.',
            'cwe'  : 'CWE-94'
        },
        'Commented-out Credentials': {
            'regex': r'(//|#|/\*).*?(password|secret|api_key)\s*[:=]',
            'desc' : 'Commented-out credentials found — potential leak.',
            'cwe'  : 'CWE-798'
        },
        'Security TODO / FIXME': {
            'regex': r'(TODO|FIXME|HACK|XXX).*(security|auth|password|vuln)',
            'desc' : 'Security-related TODO or FIXME in code.',
            'cwe'  : 'CWE-120'
        },
    },
}


# ─────────────────────────────────────────────────────────
#  TERMINAL COLORS
# ─────────────────────────────────────────────────────────

class Colors:
    RED     = '\033[91m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    GREEN   = '\033[92m'
    CYAN    = '\033[96m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'

SEVERITY_COLOR = {
    'CRITICAL': Colors.RED,
    'HIGH'    : Colors.YELLOW,
    'MEDIUM'  : Colors.BLUE,
    'LOW'     : Colors.GREEN,
}

SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']


# ─────────────────────────────────────────────────────────
#  SCANNER CLASS
# ─────────────────────────────────────────────────────────

class SecurityScanner:

    def __init__(self, target_path: str):
        self.target_path   = Path(target_path)
        self.findings      = []
        self.stats         = defaultdict(int)
        self.scanned_files = 0
        self.skipped_files = 0

    # ── file filter ──────────────────────────────────────
    def is_valid_file(self, filepath: Path) -> bool:
        if filepath.suffix not in SUPPORTED_EXTENSIONS:
            return False
        return not any(excluded in filepath.parts for excluded in EXCLUDED_DIRS)

    # ── scan a single file ───────────────────────────────
    def scan_file(self, filepath: Path):
        try:
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            self.skipped_files += 1
            return

        self.scanned_files += 1

        for severity in SEVERITY_ORDER:
            for vuln_name, cfg in PATTERNS[severity].items():
                compiled = re.compile(cfg['regex'], re.IGNORECASE)
                for line_num, line in enumerate(lines, start=1):
                    if compiled.search(line):
                        self.findings.append({
                            'severity'     : severity,
                            'vulnerability': vuln_name,
                            'file'         : str(filepath),
                            'line'         : line_num,
                            'code'         : line.strip(),
                            'description'  : cfg['desc'],
                            'cwe'          : cfg['cwe'],
                        })
                        self.stats[severity] += 1
                        break  # one finding per pattern per file

    # ── recursive project scan ───────────────────────────
    def scan_project(self):
        if not self.target_path.exists():
            print(f"{Colors.RED}[!] Error: Path not found → {self.target_path}{Colors.RESET}")
            sys.exit(1)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 62}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}   SOURCE CODE SECURITY SCANNER  —  0x2nac0nda{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 62}{Colors.RESET}")
        print(f"  Target   : {self.target_path.resolve()}")
        print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Patterns : {sum(len(v) for v in PATTERNS.values())} rules across 4 severity levels\n")

        for filepath in sorted(self.target_path.rglob('*')):
            if filepath.is_file() and self.is_valid_file(filepath):
                self.scan_file(filepath)

        # sort findings by severity priority
        self.findings.sort(
            key=lambda f: SEVERITY_ORDER.index(f['severity'])
        )

    # ── terminal report ──────────────────────────────────
    def print_report(self):
        R = Colors.RESET
        B = Colors.BOLD

        print(f"\n{B}{'─' * 62}{R}")
        print(f"{B}  SCAN SUMMARY{R}")
        print(f"{'─' * 62}")
        print(f"  Files scanned   : {self.scanned_files}")
        print(f"  Files skipped   : {self.skipped_files}")
        print(f"  Total findings  : {len(self.findings)}")
        print(f"    {SEVERITY_COLOR['CRITICAL']}{B}CRITICAL{R}  : {self.stats['CRITICAL']}")
        print(f"    {SEVERITY_COLOR['HIGH']}{B}HIGH    {R}  : {self.stats['HIGH']}")
        print(f"    {SEVERITY_COLOR['MEDIUM']}{B}MEDIUM  {R}  : {self.stats['MEDIUM']}")
        print(f"    {SEVERITY_COLOR['LOW']}{B}LOW     {R}  : {self.stats['LOW']}")
        print(f"{'─' * 62}\n")

        if not self.findings:
            print(f"  {Colors.GREEN}{B}No vulnerabilities detected.{R}\n")
            return

        for finding in self.findings:
            sev   = finding['severity']
            color = SEVERITY_COLOR[sev]

            print(f"  {color}{B}[{sev}]{R}  {B}{finding['vulnerability']}{R}")
            print(f"       CWE    : {finding['cwe']}")
            print(f"       File   : {finding['file']}")
            print(f"       Line   : {finding['line']}")
            print(f"       Info   : {finding['description']}")
            print(f"       Code   : {Colors.CYAN}{finding['code'][:90]}{R}")
            print()

    # ── JSON export ──────────────────────────────────────
    def export_json(self, output_path: str):
        report = {
            'scanner'   : 'Source Code Security Scanner',
            'author'    : '0x2nac0nda',
            'version'   : '1.0',
            'timestamp' : datetime.now().isoformat(),
            'target'    : str(self.target_path.resolve()),
            'summary'   : {
                'files_scanned' : self.scanned_files,
                'total_findings': len(self.findings),
                'critical'      : self.stats['CRITICAL'],
                'high'          : self.stats['HIGH'],
                'medium'        : self.stats['MEDIUM'],
                'low'           : self.stats['LOW'],
            },
            'findings'  : self.findings,
        }

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)

        print(f"  {Colors.GREEN}[+] JSON report saved → {output_path}{Colors.RESET}\n")


# ─────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Source Code Security Scanner — 0x2nac0nda',
        epilog='Example: python scanner.py ./my_project --json report.json'
    )
    parser.add_argument(
        'path',
        help='Target directory to scan'
    )
    parser.add_argument(
        '--json',
        metavar='FILE',
        default=None,
        help='Export findings to a JSON report file'
    )

    args = parser.parse_args()

    scanner = SecurityScanner(args.path)
    scanner.scan_project()
    scanner.print_report()

    if args.json:
        scanner.export_json(args.json)


if __name__ == '__main__':
    main()
