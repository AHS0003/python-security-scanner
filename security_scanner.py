import re
import sys
from pathlib import Path

# Règles de détection
DANGEROUS_PATTERNS = {
    "eval() usage": r"\beval\s*\(",
    "exec() usage": r"\bexec\s*\(",
    "os.system() usage": r"\bos\.system\s*\(",
    "subprocess usage": r"\bsubprocess\.",
    "Hardcoded password": r"password\s*=\s*[\"'].*[\"']",
    "Hardcoded API key": r"api_key\s*=\s*[\"'].*[\"']",
}

SEVERITY = {
    "eval() usage": "HIGH",
    "exec() usage": "HIGH",
    "os.system() usage": "HIGH",
    "subprocess usage": "MEDIUM",
    "Hardcoded password": "CRITICAL",
    "Hardcoded API key": "CRITICAL",
}


def scan_file(file_path):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

        for line_number, line in enumerate(lines, start=1):
            for issue, pattern in DANGEROUS_PATTERNS.items():
                if re.search(pattern, line):
                    findings.append({
                        "line": line_number,
                        "issue": issue,
                        "severity": SEVERITY[issue],
                        "content": line.strip()
                    })

    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)

    return findings


def print_report(findings, scanned_file):
    print("=" * 60)
    print(" SECURITY SCAN REPORT ")
    print("=" * 60)
    print(f"Scanned file: {scanned_file}")
    print(f"Total issues found: {len(findings)}")
    print("=" * 60)

    if not findings:
        print("No security issues detected.")
        return

    for finding in findings:
        print(f"""
[!] {finding['severity']}
Line    : {finding['line']}
Issue   : {finding['issue']}
Code    : {finding['content']}
""")


def main():
    if len(sys.argv) != 2:
        print("Usage: python security_scanner.py <python_file>")
        sys.exit(1)

    target_file = sys.argv[1]

    if not Path(target_file).exists():
        print(f"[ERROR] File does not exist: {target_file}")
        sys.exit(1)

    findings = scan_file(target_file)
    print_report(findings, target_file)


if __name__ == "__main__":
    main()