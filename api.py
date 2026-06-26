"""
API REST – Agent SAST Python
Expose le moteur de scan via des endpoints HTTP.

Usage :
    pip install flask
    python api.py

Endpoints :
    POST /scan/file   – Analyse un fichier uploadé
    POST /scan/code   – Analyse du code envoyé en JSON
    GET  /health      – Health check
    GET  /rules       – Liste des règles de détection actives
"""

import os
import tempfile
import datetime
from flask import Flask, request, jsonify
from security_scanner import scan_file, DANGEROUS_PATTERNS, SEVERITY, REMEDIATION

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB max


# ─── Helper ───────────────────────────────────────────────────────────────────

def _build_report(findings: list, source: str) -> dict:
    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_count[f["severity"]] += 1
    return {
        "status":           "ok",
        "source":           source,
        "timestamp":        datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_issues":     len(findings),
        "severity_summary": severity_count,
        "findings":         findings,
    }


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify({
        "status": "healthy",
        "agent":  "SAST Python Agent v1.0",
        "rules":  len(DANGEROUS_PATTERNS),
        "time":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })


@app.get("/rules")
def list_rules():
    rules = [
        {
            "id":          name,
            "severity":    SEVERITY[name],
            "pattern":     pattern,
            "remediation": REMEDIATION[name],
        }
        for name, pattern in DANGEROUS_PATTERNS.items()
    ]
    return jsonify({"total_rules": len(rules), "rules": rules})


@app.post("/scan/file")
def scan_uploaded_file():
    """
    Analyse un fichier Python uploadé (multipart/form-data).

    curl -X POST http://localhost:5000/scan/file -F "file=@sample_vulnerable.py"
    """
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "Champ 'file' manquant."}), 400

    uploaded = request.files["file"]
    if not uploaded.filename.endswith(".py"):
        return jsonify({"status": "error", "message": "Seuls les fichiers .py sont acceptés."}), 415

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
        uploaded.save(tmp.name)
        tmp_path = tmp.name

    try:
        findings = scan_file(tmp_path)
        report   = _build_report(findings, uploaded.filename)
    finally:
        os.unlink(tmp_path)

    return jsonify(report)


@app.post("/scan/code")
def scan_inline_code():
    """
    Analyse du code Python envoyé en JSON.

    curl -X POST http://localhost:5000/scan/code \\
         -H "Content-Type: application/json" \\
         -d '{"code": "password = \\"admin123\\"\\neval(input())"}'
    """
    body = request.get_json(silent=True)
    if not body or "code" not in body:
        return jsonify({"status": "error", "message": "Champ 'code' manquant."}), 400

    filename = body.get("filename", "inline_snippet.py")

    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", encoding="utf-8", delete=False) as tmp:
        tmp.write(body["code"])
        tmp_path = tmp.name

    try:
        findings = scan_file(tmp_path)
        report   = _build_report(findings, filename)
    finally:
        os.unlink(tmp_path)

    return jsonify(report)


# ─── Lancement ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    print(f"""

   🔐  Agent SAST – API REST démarrée    
   http://localhost:{port:<5}               

  GET  /health      → Health check
  GET  /rules       → Règles actives ({len(DANGEROUS_PATTERNS)})
  POST /scan/file   → Analyse un fichier uploadé
  POST /scan/code   → Analyse du code inline (JSON)
""")
    app.run(host="0.0.0.0", port=port, debug=debug)