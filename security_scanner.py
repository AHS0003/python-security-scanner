"""
Agent SAST Python – Détection de vulnérabilités applicatives
Autonomous static analysis agent exposable via REST API
"""

import re
import sys
import json
import datetime
from pathlib import Path


# ─── Règles de détection ──────────────────────────────────────────────────────

DANGEROUS_PATTERNS = {
    "eval() usage":       r"\beval\s*\(",
    "exec() usage":       r"\bexec\s*\(",
    "os.system() usage":  r"\bos\.system\s*\(",
    "subprocess usage":   r"\bsubprocess\.",
    "Hardcoded password": r"password\s*=\s*[\"'].*[\"']",
    "Hardcoded API key":  r"api_key\s*=\s*[\"'].*[\"']",
}

SEVERITY = {
    "eval() usage":       "HIGH",
    "exec() usage":       "HIGH",
    "os.system() usage":  "HIGH",
    "subprocess usage":   "MEDIUM",
    "Hardcoded password": "CRITICAL",
    "Hardcoded API key":  "CRITICAL",
}

REMEDIATION = {
    "eval() usage":       "Remplacez eval() par ast.literal_eval() ou une logique métier explicite.",
    "exec() usage":       "Évitez exec() ; utilisez des fonctions définies statiquement.",
    "os.system() usage":  "Utilisez subprocess.run() avec une liste d'arguments et shell=False.",
    "subprocess usage":   "Assurez-vous que shell=False et que les arguments sont une liste.",
    "Hardcoded password": "Stockez les secrets dans des variables d'environnement ou un vault.",
    "Hardcoded API key":  "Utilisez os.getenv() ou python-dotenv ; ne commitez jamais de clés en clair.",
}


# ─── Moteur d'analyse ─────────────────────────────────────────────────────────

def scan_file(file_path: str) -> list[dict]:
    """Scanne un fichier Python et retourne la liste des vulnérabilités détectées."""
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] Fichier introuvable : {file_path}")
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission refusée : {file_path}")
        sys.exit(1)

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for issue, pattern in DANGEROUS_PATTERNS.items():
            if re.search(pattern, line):
                findings.append({
                    "line":        line_number,
                    "issue":       issue,
                    "severity":    SEVERITY[issue],
                    "content":     stripped,
                    "remediation": REMEDIATION[issue],
                })

    return findings


def scan_directory(dir_path: str) -> dict:
    """Scanne récursivement tous les fichiers .py d'un répertoire."""
    results = {}
    for py_file in Path(dir_path).rglob("*.py"):
        findings = scan_file(str(py_file))
        if findings:
            results[str(py_file)] = findings
    return results


# ─── Rapport CLI ──────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_COLOR = {
    "CRITICAL": "\033[95m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[94m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_report(findings: list[dict], scanned_file: str, fmt: str = "text") -> None:
    """Affiche le rapport de scan en mode texte ou JSON."""

    if fmt == "json":
        report = {
            "scanned_file": scanned_file,
            "timestamp":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "total_issues": len(findings),
            "findings":     sorted(findings, key=lambda x: SEVERITY_ORDER[x["severity"]]),
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    print(f"\n{BOLD}{'═' * 62}{RESET}")
    print(f"{BOLD}    AGENT SAST – RAPPORT DE SÉCURITÉ{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}")
    print(f"  Fichier analysé : {scanned_file}")
    print(f"  Horodatage      : {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  Problèmes       : {BOLD}{len(findings)}{RESET}")
    print(f"{BOLD}{'─' * 62}{RESET}")

    if not findings:
        print(f"\n   Aucun problème de sécurité détecté.\n")
        return

    for f in sorted(findings, key=lambda x: SEVERITY_ORDER[x["severity"]]):
        color = SEVERITY_COLOR.get(f["severity"], "")
        print(f"""
  {color}{BOLD}[{f['severity']}]{RESET}  {f['issue']}
  Ligne       : {f['line']}
  Code        : {f['content']}
  Remédiation : {f['remediation']}""")

    print(f"\n{BOLD}{'─' * 62}{RESET}")
    print(f"{BOLD}  Résumé :{RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sum(1 for f in findings if f["severity"] == sev)
        if count:
            print(f"    {SEVERITY_COLOR[sev]}{sev:<10}{RESET} : {count}")
    print(f"{BOLD}{'═' * 62}{RESET}\n")


# ─── Point d'entrée CLI ───────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Agent SAST Python – détection de vulnérabilités applicatives"
    )
    parser.add_argument("target", help="Fichier ou répertoire Python à analyser")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Format de sortie : text (défaut) ou json"
    )
    args = parser.parse_args()

    target = Path(args.target)

    if target.is_dir():
        all_results = scan_directory(str(target))
        if not all_results:
            print("Aucun problème détecté dans le répertoire.")
            return
        for file_path, findings in all_results.items():
            print_report(findings, file_path, fmt=args.format)
    elif target.is_file():
        findings = scan_file(str(target))
        print_report(findings, str(target), fmt=args.format)
    else:
        print(f"[ERROR] Cible invalide : {args.target}")
        sys.exit(1)


if __name__ == "__main__":
    main()