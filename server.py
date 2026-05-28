#!/usr/bin/env python3
"""
DFIR C2 Server — Secure Collection Receiver (HTTPS Enabled)
==========================================================
A Flask server that receives Base64-encoded ZIP bundles via HTTPS,
verifies integrity, and provides a monitoring dashboard.
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

from flask import Flask, Response, jsonify, request, render_template_string

# Configuration

UPLOAD_ROOT = Path(os.path.expanduser("~")) / "Desktop" / "Forensic_Data"
MAX_PAYLOAD_MB = 100

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_PAYLOAD_MB * 1024 * 1024

# Dashboard UI

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>DFIR C2 — Secure Dashboard</title>
    <style>
        :root {
            --bg-primary: #0a0e17; --bg-card: #111827; --border: #1e293b;
            --accent: #3b82f6; --green: #10b981; --red: #ef4444;
            --text-primary: #f1f5f9; --text-muted: #64748b;
        }
        body { font-family: sans-serif; background: var(--bg-primary); color: var(--text-primary); padding: 2rem; }
        .container { max-width: 1100px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 2rem; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: var(--bg-card); padding: 1.5rem; border-radius: 12px; border: 1px solid var(--border); }
        .stat-label { color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; }
        .stat-value { font-size: 1.8rem; font-weight: bold; margin-top: 0.5rem; }
        table { width: 100%; border-collapse: collapse; background: var(--bg-card); border-radius: 12px; overflow: hidden; }
        th { text-align: left; padding: 1rem; background: rgba(0,0,0,0.3); color: var(--text-muted); font-size: 0.75rem; }
        td { padding: 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
        .integrity-pass { color: var(--green); font-weight: bold; }
        .integrity-fail { color: var(--red); font-weight: bold; }
        .badge { padding: 0.2rem 0.5rem; border-radius: 4px; background: var(--accent); font-size: 0.7rem; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1 style="color: var(--accent)"> DFIR C2 Dashboard</h1>
                <p style="color: var(--text-muted)">Secure Forensic Data Acquisition</p>
            </div>
            <div style="text-align: right">
                <span class="badge">SSL/TLS ENABLED</span>
                <p style="font-size: 0.8rem; margin-top: 5px">Status: Listening</p>
            </div>
        </header>

        <div class="stats">
            <div class="stat-card"><div class="stat-label">Total Collections</div><div class="stat-value">{{ total }}</div></div>
            <div class="stat-card"><div class="stat-label">Unique Hosts</div><div class="stat-value">{{ unique_hosts }}</div></div>
            <div class="stat-card"><div class="stat-label">Storage Path</div><div class="stat-value" style="font-size: 0.8rem">{{ storage }}</div></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>TIMESTAMP (UTC)</th>
                    <th>SOURCE IP</th>
                    <th>HOSTNAME</th>
                    <th>SIZE</th>
                    <th>INTEGRITY</th>
                </tr>
            </thead>
            <tbody>
                {% for c in collections %}
                <tr>
                    <td>{{ c.timestamp }}</td>
                    <td><code>{{ c.ip }}</code></td>
                    <td><strong>{{ c.hostname }}</strong></td>
                    <td>{{ c.size }}</td>
                    <td class="{{ 'integrity-pass' if c.integrity else 'integrity-fail' }}">
                        {{ '✓ VERIFIED' if c.integrity else '✗ FAILED' }}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

# Helpers

def _verify_manifest(zip_bytes: bytes) -> bool:
    try:
        with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
            if "manifest.json" not in zf.namelist(): return False
            manifest = json.loads(zf.read("manifest.json"))
            for filename, expected_hash in manifest.items():
                actual = hashlib.sha256(zf.read(filename)).hexdigest()
                if actual != expected_hash: return False
        return True
    except: return False

def _human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB"):
        if nbytes < 1024: return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} GB"

def _get_collections() -> list:
    collections = []
    if not UPLOAD_ROOT.exists(): return collections
    for folder in sorted(UPLOAD_ROOT.iterdir(), reverse=True):
        if not folder.is_dir(): continue
        meta_path = folder / "meta.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                collections.append({
                    "timestamp": meta.get("timestamp", "?"),
                    "ip": meta.get("source_ip", "?"),
                    "hostname": meta.get("hostname", "?"),
                    "size": _human_size(meta.get("bundle_size_bytes", 0)),
                    "integrity": meta.get("integrity_verified", False),
                })
            except: continue
    return collections

# Routes

@app.route("/")
def dashboard():
    cols = _get_collections()
    return render_template_string(
        DASHBOARD_HTML,
        collections=cols,
        total=len(cols),
        unique_hosts=len({c["hostname"] for c in cols}),
        storage=str(UPLOAD_ROOT)
    )

@app.route("/upload", methods=["POST"])
def upload():
    source_ip = request.remote_addr or "unknown"
    
    # Check Custom Auth Header (Matches Agent)
    if request.headers.get("X-C2-Auth") != "Forensic-Auth-99":
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    payload = request.get_json(silent=True)
    if not payload or "data" not in payload:
        return jsonify({"status": "error", "message": "Invalid Payload"}), 400

    try:
        zip_bytes = base64.b64decode(payload["data"])
    except:
        return jsonify({"status": "error", "message": "B64 Decode Fail"}), 400

    integrity_ok = _verify_manifest(zip_bytes)
    
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder_name = f"{ts}_{source_ip.replace(':', '_')}"
    dest = UPLOAD_ROOT / folder_name
    dest.mkdir(parents=True, exist_ok=True)

    (dest / "bundle.zip").write_bytes(zip_bytes)
    
    # Extract
    try:
        with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
            zf.extractall(dest / "extracted")
    except: pass

    # Metadata
    meta = {
        "source_ip": source_ip,
        "hostname": payload.get("hostname", "unknown"),
        "timestamp": payload.get("timestamp", ts),
        "bundle_size_bytes": len(zip_bytes),
        "integrity_verified": integrity_ok,
    }
    (dest / "meta.json").write_text(json.dumps(meta, indent=2))

    return jsonify({"status": "success", "integrity": integrity_ok}), 200

# Main Entry

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()

    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

    print(f"""
     ______________________________________________   
    |DFIR C2 Server Started                
    |Protocol : HTTPS (SSL/TLS)            
    |Port     : {args.port}                
    |Storage  : {UPLOAD_ROOT.resolve()}    
    |C2_URL   : https://127.0.0.1:8443
    |______________________________________________
    """)

    # 'adhoc' context generates a temporary self-signed certificate.
    # Requirement: pip install pyopenssl
    app.run(host="0.0.0.0", port=args.port, ssl_context='adhoc')

if __name__ == "__main__":
    main()