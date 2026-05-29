# Secure DFIR Telemetry & C2 System

A Python-based Digital Forensics and Incident Response (DFIR) tool designed for automated volatile data acquisition, secure exfiltration, and centralized monitoring.

## Key Features
- **Secure Transport:** HTTPS exfiltration with custom authentication headers.
- **Data Integrity:** Automatic SHA-256 manifest generation to ensure evidence authenticity.
- **Deep Forensics:** Scans browser history (Chrome/Edge), network connections, and Registry persistence.
- **Anti-Forensics:** Utilizes in-memory ZIP bundling (`io.BytesIO`) to minimize disk footprints.
- **Persistence:** Automated Windows Startup integration for continuous monitoring.

## Tech Stack
- **Language:** Python 3.12+
- **Backend:** Flask (HTTPS Enabled)
- **Libraries:** Psutil, Requests, Pillow, PyOpenSSL

## Installation & Usage
1. Install dependencies:
   `pip install flask requests psutil pillow pyopenssl`
2. Start the C2 Server:
   `python server.py`
3. Deploy the Agent:
   `python agent.py`
