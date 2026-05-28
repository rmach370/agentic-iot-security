# IoT Security Agent — ECE202C Spring 26

## Overview
An autonomous AI security agent that performs multi-phase penetration testing on a simulated IoT smart camera. The agent uses ChatGPT (OpenAI) as its reasoning core and a suite of custom security tools to systematically discover, analyze, and report vulnerabilities.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     main.py — Agent Loop                │
│                                                         │
│  User prompt → ChatGPT (mini 4o) → Tool calls → Results    │
│                     ↑                          │        │
│                     └──────── feedback ────────┘        │
└─────────────────────────────────────────────────────────┘
          │ calls
          ▼
┌─────────────────────────────────────────────────────────┐
│                    tools.py — Tool Suite                │
│                                                         │
│  probe_endpoint       → HTTP request + header capture  │
│  analyze_headers      → Security header audit          │
│  test_credentials     → Brute force + enumeration      │
│  scan_for_secrets     → Regex secret scanner           │
│  test_auth_bypass     → Auth bypass techniques         │
│  lookup_cve           → CVE database lookup            │
│  analyze_firmware_config → Config security audit       │
└─────────────────────────────────────────────────────────┘
          │ targets
          ▼
┌─────────────────────────────────────────────────────────┐
│                  app.py — Target Device                 │
│                                                         │
│  Simulated SmartEye-Pro-v2 IoT camera                  │
│  10 endpoints with intentional layered vulnerabilities  │
└─────────────────────────────────────────────────────────┘
```

---

## Investigation Phases

| Phase | Goal | Tools Used |
|-------|------|-----------|
| 1 — Recon | Map all endpoints, collect version info | `probe_endpoint`, `analyze_headers` |
| 2 — Auth | Break authentication, test default creds | `test_credentials`, `test_auth_bypass` |
| 3 — Deep Dive | Extract secrets, audit config, CVE lookup | `scan_for_secrets`, `lookup_cve`, `analyze_firmware_config` |
| 4 — Report | Structure findings into security report | (LLM synthesis) |

---

## Agentic Behavior

The agent demonstrates:
- **Multi-step planning**: Follows a phased investigation strategy
- **Adaptation**: Uses findings from one endpoint to inform actions on others (e.g., credentials found in `/logs` are tested at `/auth/login`)
- **Tool chaining**: `probe_endpoint` → `analyze_headers` → `scan_for_secrets` in sequence
- **Dead-end handling**: If auth fails, tries bypass; if bypass fails, moves on
- **Reasoning transparency**: Logs LLM reasoning at each step

---

## Intentional Vulnerabilities in app.py

| ID | Type | Endpoint | Severity |
|----|------|----------|----------|
| V1 | Default credentials never changed | `/auth/login` | CRITICAL |
| V2 | Credentials in plaintext response | `/logs` | CRITICAL |
| V3 | Unauthenticated stream with creds in URL | `/stream` | CRITICAL |
| V4 | Debug endpoint exposed in production | `/debug` | HIGH |
| V5 | Command injection surface | `/debug?cmd=` | HIGH |
| V6 | WiFi PSK in plaintext config | `/config` | HIGH |
| V7 | Firmware update over HTTP (no HTTPS) | `/firmware/update` | HIGH |
| V8 | Unsigned firmware accepted | `/firmware/update` | CRITICAL |
| V9 | Version/server info in headers | `/` | MEDIUM |
| V10 | TLS verification disabled for cloud | `/config` | HIGH |
| V11 | MQTT credentials in env | `/debug` | HIGH |
| V12 | User enumeration via error messages | `/auth/login` | MEDIUM |
| V13 | MD5 session tokens | `/auth/login` | MEDIUM |
| V14 | Token accepted in query parameter | all auth | MEDIUM |
| V15 | Internal IP addresses leaked | `/status` | LOW |

---

## Running the Project

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Terminal 1 — start the target
python app.py

# 3. Terminal 2 — run the agent (set OPENAI_API_KEY first)
export OPENAI_API_KEY=your_key_here
python main.py
```

Logs are written to `logs/agent_log_<timestamp>.json`  
Reports are written to `logs/security_report_<timestamp>.md`

---

## File Structure

```
iot_security_agent/
├── app.py              # Simulated vulnerable IoT camera
├── main.py             # Autonomous security agent
├── tools.py            # Security analysis tool suite
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── logs/               # Agent logs and reports (generated)
```

---

## AI Limitations Observed

- The agent occasionally re-checks already-visited endpoints (mitigated by tracking visited state in prompt context)
- CVE lookup is local/simulated; a real agent would query NVD API
- The agent cannot actually execute shell commands (command injection is simulated)
- LLM may not always chain findings optimally (e.g., sometimes tests creds before finding them in logs)
