# 🛡️ Agentic AI SOC Analyst ⚡

[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104.0-009688.svg?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Stateful%20DAG-8B5CF6.svg?style=flat&logo=chainlink&logoColor=white)](https://github.com/langchain-ai/langgraph)
[![HTMX](https://img.shields.io/badge/HTMX-1.9.5-3D72D7.svg?style=flat&logo=htmx&logoColor=white)](https://htmx.org/)
[![Docker](https://img.shields.io/badge/Docker-Desktop-2496ED.svg?style=flat&logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg?style=flat)](https://opensource.org/licenses/MIT)

An autonomous, production-grade **Security Operations Center (SOC) Analyst** built on top of **Wazuh SIEM**. The system intercepts security events from your Windows host, processes them through a stateful multi-agent LangGraph pipeline, enriches them with multi-vendor threat intelligence, and presents a premium, real-time response dashboard with Human-in-the-Loop (HITL) active containment.

---

## 🌌 The Dashboard Aesthetic

The SOC dashboard features a custom **"Geospatial Luminescence"** dark mode theme (based on Stitch design tokens):
*   **Color Palette**: Deep Space Navy background (`#0e1322`) and translucent card surfaces (`rgba(22, 27, 43, 0.7)`) with backdrop blurs.
*   **Signature Lighting**: Active elements glow with Electric Cyan (`#00fbfb`) and Neon Purple (`#ecb1ff`).
*   **Dynamic Interactions**: CSS transitions powered by cubic-bezier curves combined with **HTMX** for smooth, zero-refresh single-page transitions.

---

## 🛠️ Key Capabilities & Shield Mechanisms

### 🧠 1. Multi-Agent LangGraph Triage
Instead of single-prompt AI reasoning, the system orchestrates **6 specialized collaborating agents** in a directed acyclic graph (DAG):
1.  **Gate Agent**: Performs prompt injection defense and parses raw logs into facts.
2.  **Triage Agent**: Classifies attack categories (ransomware, brute force, etc.) and gauges severity.
3.  **Endpoint Agent**: Polls live process trees and FIM records from the host via Wazuh APIs.
4.  **Threat Intel Agent**: Queries VT, AbuseIPDB, and AlienVault OTX in parallel.
5.  **Correlation Agent**: Scans database history (Postgres) and past incident reports (ChromaDB).
6.  **Decision Agent**: Synthesizes all data, writes the markdown triage report, and issues containment requests.

### 🛡️ 2. Dual-LLM Injection Defense
To secure the AI against log-injection attacks:
*   **Stage 1: Heuristic Filter**: Stops common override patterns before LLM execution.
*   **Stage 2: Quarantined JSON Fact Extraction**: An isolated LLM extracts facts to JSON without reasoning.
*   **Stage 3: Privileged Evaluation**: The decision LLM only sees sanitized facts, making prompt injection impossible.

### 🔌 3. Decoupled Cross-Vendor Connectors
Zero-config modular connectors (Wazuh, AWS GuardDuty, Okta, Microsoft Defender) that can be toggled between `MOCK` and `LIVE` collection in real-time from the settings panel.

---

## 🧭 System Architecture

```
                                  +-----------------------+
                                  |   Wazuh Agent (Host)  |
                                  +-----------------------+
                                              |
                                              v
+------------------+                    +-----------+
| Mock Connectors  | --(10s Poll)-----> |  FastAPI  | <---(HTMX Poll)--- +----------------+
| (Okta/AWS/Def)   |                    |  Backend  |                    | Jinja2 Web UI  |
+------------------+                    +-----------+                    | (Port 8080)    |
                                         |         |                     +----------------+
                   +---------------------+         +------------+
                   v                                            v
     +---------------------------+                +----------------------------+
     | PostgreSQL (Partitioned)  |                |   LangGraph Agent Pipeline |
     | - Normalised Alerts Table |                |   - Gate / Triage / Intel  |
     | - Response Actions Queue  |                |   - Postgres & ChromaDB Mem |
     +---------------------------+                +----------------------------+
```

---

## 🚀 Quick Start Guide

### Prerequisites
*   Windows 10/11 with WSL2 enabled.
*   Docker Desktop running.
*   Python 3.11+ installed.

### 1. Boot up the Database & SIEM Stack
Deploy PostgreSQL, ChromaDB, and the Wazuh stack via Docker Compose:
```bash
docker-compose up -d
```

### 2. Set Up the Local Environment
Configure python dependencies:
```bash
# Install packages
pip install -r requirements.txt
```

### 3. Run the Dashboard & Backend Server
Start the FastAPI server:
```bash
python -m uvicorn soc_analyst.api.main:app --reload --host 127.0.0.1 --port 8080
```
Open **[http://127.0.0.1:8080](http://127.0.0.1:8080)** in your browser.
*   **Username**: `admin`
*   **Password**: `socadmin2026`

---

## ⚡ Try Live Threat Simulations!

To watch the automated threat-hunting pipeline execute in real-time, open a separate **Administrator PowerShell** window and run one of our built-in simulator scripts:

*   **Local Account Creation** (Local Privilege Escalation):
    ```powershell
    net user securitytest operatorpass123! /add
    ```
    *Wazuh Rule triggered: 61100 (Windows Audit: User account created)*

*   **Base64 Encoded Script Execution** (Defense Evasion):
    ```powershell
    powershell -EncodedCommand JgAgACcAdwByAGkAdABlAC0AaABvAHMAdAAnACAAJwBIAGUAbABsAG8AIABmAHIAbwBtACAAQQBJACcADwA=
    ```
    *Wazuh Rule triggered: 91000 (PowerShell Encoded Command execution)*

*   **Suspicious Scheduled Task Creation** (Malicious Persistence):
    ```powershell
    schtasks /create /tn "DiagnosticPatch" /tr "cmd.exe /c echo 'patching'" /sc daily /st 12:00
    ```
    *Wazuh Rule triggered: 61100 (Windows Audit: Scheduled Task Created)*

*Watch the alert pop up on your dashboard within 10 seconds, inspect the generated AI Triage Report containing your host's running processes, and approve the containment actions in the Response Center!*

---

## ⚙️ Service Ports Map

| Service | Port / URL | Credentials |
|---------|------------|-------------|
| **SOC Dashboard Web** | `http://127.0.0.1:8080` | `admin` / `socadmin2026` |
| **Wazuh Dashboard** | `https://localhost:443` | `admin` / `socadmin2026` |
| **Wazuh REST API** | `https://localhost:56000` | `wazuh-wui` / `MyS3cr37P450r.*-` |
| **PostgreSQL** | `localhost:5432` | `soc_user` / `soc_password` |
| **ChromaDB Vector** | `localhost:8001` | — |
| **Docker Registry Image** | `madmaxboi/agenticaisocanalyst` | — |

---

## 📄 Reference Documentation

For a detailed review of the architecture decisions, development stages (Phases 1-11), folder layout structures, and deeper explanations of the LangGraph DAG configuration, refer to the private document:
`C:\Users\mmddf\.gemini\antigravity\brain\ddf0b3e7-bc31-4063-884c-f5d781c6f688\agentic_soc_analyst_reference_guide.md`
