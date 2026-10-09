
"""
API REST - Agent SAST Python
Expose le moteur de scan via des endpoints HTTP.

Endpoints :
    GET  /health      - Health check
    GET  /rules       - Liste des règles de détection
    GET  /metrics     - Métriques Prometheus
    POST /scan/file   - Analyse d'un fichier Python
    POST /scan/code   - Analyse du code envoyé en JSON
"""

import os
import tempfile
import datetime

from flask import Flask, request, jsonify, Response

from prometheus_client import (
    Counter,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST
)

from security_scanner import (
    scan_file,
    DANGEROUS_PATTERNS,
    SEVERITY,
    REMEDIATION
)


# ============================================================
# CONFIGURATION FLASK
# ============================================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


# ============================================================
# PROMETHEUS METRICS
# ============================================================

# Nombre total de scans réussis
SCANS_TOTAL = Counter(
    "sast_scans_total",
    "Total number of completed SAST scans"
)

# Nombre cumulé de vulnérabilités détectées
FINDINGS_TOTAL = Counter(
    "sast_findings_total",
    "Total vulnerabilities detected by severity",
    ["severity"]
)

# Vulnérabilités du dernier scan
LAST_SCAN_FINDINGS = Gauge(
    "sast_last_scan_findings",
    "Number of vulnerabilities in the last scan",
    ["severity"]
)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Initialiser les métriques à zéro
for severity in SEVERITIES:
    FINDINGS_TOTAL.labels(severity=severity).inc(0)
    LAST_SCAN_FINDINGS.labels(severity=severity).set(0)


# ============================================================
# HELPER - BUILD SCAN REPORT
# ============================================================

def _build_report(findings: list, source: str) -> dict:

    severity_count = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        severity = finding["severity"]
        severity_count[severity] += 1

    # Mettre à jour les métriques Prometheus
    SCANS_TOTAL.inc()

    for severity, count in severity_count.items():

        # Nombre cumulé de vulnérabilités
        FINDINGS_TOTAL.labels(
            severity=severity
        ).inc(count)

        # Résultat du dernier scan
        LAST_SCAN_FINDINGS.labels(
            severity=severity
        ).set(count)

    return {
        "status": "ok",
        "source": source,
        "timestamp": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
        "total_issues": len(findings),
        "severity_summary": severity_count,
        "findings": findings,
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health():

    return jsonify({
        "status": "healthy",
        "agent": "SAST Python Agent v1.0",
        "rules": len(DANGEROUS_PATTERNS),
        "time": datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat(),
    })


# ============================================================
# LIST SECURITY RULES
# ============================================================

@app.get("/rules")
def list_rules():

    rules = [
        {
            "id": name,
            "severity": SEVERITY[name],
            "pattern": pattern,
            "remediation": REMEDIATION[name],
        }
        for name, pattern in DANGEROUS_PATTERNS.items()
    ]

    return jsonify({
        "total_rules": len(rules),
        "rules": rules
    })


# ============================================================
# PROMETHEUS ENDPOINT
# ============================================================

@app.get("/metrics")
def metrics():

    return Response(
        generate_latest(),
        content_type=CONTENT_TYPE_LATEST
    )


# ============================================================
# SCAN UPLOADED PYTHON FILE
# ============================================================

@app.post("/scan/file")
def scan_uploaded_file():

    if "file" not in request.files:
        return jsonify({
            "status": "error",
            "message": "Champ 'file' manquant."
        }), 400

    uploaded = request.files["file"]

    if not uploaded.filename or not uploaded.filename.endswith(".py"):
        return jsonify({
            "status": "error",
            "message": "Seuls les fichiers .py sont acceptés."
        }), 415

    with tempfile.NamedTemporaryFile(
        suffix=".py",
        delete=False
    ) as tmp:

        uploaded.save(tmp.name)
        tmp_path = tmp.name

    try:
        findings = scan_file(tmp_path)

        report = _build_report(
            findings,
            uploaded.filename
        )

    finally:
        os.unlink(tmp_path)

    return jsonify(report)


# ============================================================
# SCAN INLINE PYTHON CODE
# ============================================================

@app.post("/scan/code")
def scan_inline_code():

    body = request.get_json(silent=True)

    if not isinstance(body, dict) or not isinstance(body.get("code"), str):
        return jsonify({
            "status": "error",
            "message": "Champ 'code' manquant ou invalide."
        }), 400

    filename = body.get(
        "filename",
        "inline_snippet.py"
    )

    with tempfile.NamedTemporaryFile(
        suffix=".py",
        mode="w",
        encoding="utf-8",
        delete=False
    ) as tmp:

        tmp.write(body["code"])
        tmp_path = tmp.name

    try:
        findings = scan_file(tmp_path)

        report = _build_report(
            findings,
            filename
        )

    finally:
        os.unlink(tmp_path)

    return jsonify(report)


# ============================================================
# APPLICATION STARTUP
# ============================================================

if __name__ == "__main__":

    port = int(os.getenv("PORT", 5000))

    debug = (
        os.getenv("FLASK_DEBUG", "false").lower() == "true"
    )

    print(f"""
    ==============================================
       Python SAST Agent - REST API
    ==============================================

    Application: http://localhost:{port}

    GET  /health       - Health check
    GET  /rules        - Security rules
    GET  /metrics      - Prometheus metrics
    POST /scan/file    - Scan Python file
    POST /scan/code    - Scan inline Python code

    ==============================================
    """)

    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug
    )
