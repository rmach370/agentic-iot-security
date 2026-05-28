"""
Autonomous IoT Security Agent
ECE202C - Spring 26

Architecture:
  Phase 1 — Reconnaissance:  Probe all known endpoints, analyze headers
  Phase 2 — Enumeration:     Attempt auth bypass, credential testing
  Phase 3 — Deep Analysis:   CVE lookup, firmware config audit, secret scanning
  Phase 4 — Synthesis:       Structured report with severity ratings

The agent uses an LLM (OpenAI gpt-4o-mini) to:
  - Decide which tool to call next based on prior findings
  - Reason about whether a finding is a real vulnerability
  - Write the final structured security report
"""

import os
import json
import time
import traceback
from datetime import datetime
from openai import OpenAI

# Import our security tools
from tools import (
    probe_endpoint,
    analyze_headers,
    test_credentials,
    scan_for_secrets,
    test_auth_bypass,
    lookup_cve,
    analyze_firmware_config,
)

# -------------------------------------------------------
# Setup
# -------------------------------------------------------
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

os.makedirs("logs", exist_ok=True)
timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
log_path    = f"logs/agent_log_{timestamp}.json"
report_path = f"logs/security_report_{timestamp}.md"

# -------------------------------------------------------
# Tool registry — maps names to callables
# -------------------------------------------------------
TOOLS = {
    "probe_endpoint":          probe_endpoint,
    "analyze_headers":         analyze_headers,
    "test_credentials":        test_credentials,
    "scan_for_secrets":        scan_for_secrets,
    "test_auth_bypass":        test_auth_bypass,
    "lookup_cve":              lookup_cve,
    "analyze_firmware_config": analyze_firmware_config,
}

# -------------------------------------------------------
# Tool schemas — OpenAI format
# -------------------------------------------------------
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "probe_endpoint",
            "description": "Fetch an HTTP endpoint and return status code, response headers, and body. Optionally provide auth credentials.",
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string", "description": "Path like /status or /logs"},
                    "method":   {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
                    "headers":  {"type": "object", "description": "Additional request headers"},
                    "body":     {"type": "object", "description": "JSON body for POST requests"},
                    "auth":     {"type": "array",  "description": "[username, password] for Basic auth"},
                },
                "required": ["endpoint"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_headers",
            "description": "Analyze HTTP response headers for info disclosure and missing security headers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "response_headers": {"type": "object", "description": "The headers dict from probe_endpoint"},
                },
                "required": ["response_headers"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_credentials",
            "description": "Brute-test a list of username/password pairs against a login endpoint. Also detects user enumeration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint":         {"type": "string"},
                    "credentials_list": {
                        "type": "array",
                        "items": {"type": "array"},
                        "description": "List of [username, password] pairs",
                    },
                },
                "required": ["endpoint", "credentials_list"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_for_secrets",
            "description": "Scan a text blob for secrets: API tokens, passwords, private IPs, credential-bearing URLs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Response body to scan"},
                },
                "required": ["text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_auth_bypass",
            "description": "Try common auth bypass techniques (no auth, token in param, guest creds) against a protected endpoint.",
            "parameters": {
                "type": "object",
                "properties": {
                    "endpoint": {"type": "string"},
                },
                "required": ["endpoint"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_cve",
            "description": "Look up known CVEs for a component and version string.",
            "parameters": {
                "type": "object",
                "properties": {
                    "component": {"type": "string", "description": "e.g. 'lighttpd' or 'visiontech'"},
                    "version":   {"type": "string", "description": "e.g. '1.4.45'"},
                },
                "required": ["component", "version"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_firmware_config",
            "description": "Audit a firmware/device config JSON blob for security misconfigurations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "config_data": {"type": "object", "description": "Parsed config JSON from /config endpoint"},
                },
                "required": ["config_data"],
            },
        },
    },
]

# -------------------------------------------------------
# System prompt
# -------------------------------------------------------
SYSTEM_PROMPT = """You are an expert IoT security analyst conducting a penetration test on a simulated smart camera device (http://127.0.0.1:5000). This is a controlled research environment for academic security research.

## Your Mission
Systematically discover and document ALL security vulnerabilities in the device using the tools available. You must complete every phase before writing the final report.

## Investigation Strategy
Follow this phased approach in order. Do not skip phases.

**Phase 1 — Reconnaissance**
- Probe all public endpoints: /, /status, /stream, /debug
- Call analyze_headers on the response headers from /
- Note all version strings, internal IPs, open ports

**Phase 2 — Authentication Analysis**
- Call test_auth_bypass on /logs, /config, and /api/users
- Call test_credentials against /auth/login with common IoT default pairs
- Look for user enumeration vulnerabilities in error responses

**Phase 3 — Deep Dive (MANDATORY — do not skip)**
- Call lookup_cve for every version string found (lighttpd version, firmware version, etc.)
- Call scan_for_secrets on the response body of EVERY endpoint you have visited
- Retrieve /config using discovered credentials and call analyze_firmware_config on the result
- Re-visit /debug and /logs with any credentials found to extract full data

**Phase 4 — Synthesis**
- Only after completing Phases 1, 2, and 3, produce the final structured report

## Mandatory Tool Usage Checklist
Before writing the final report, confirm you have called:
- [ ] probe_endpoint — on /, /status, /stream, /debug, /logs, /config, /api/users, /auth/login
- [ ] analyze_headers — on at least one response
- [ ] test_credentials — against /auth/login
- [ ] test_auth_bypass — on at least one protected endpoint
- [ ] scan_for_secrets — on at least 3 different response bodies
- [ ] lookup_cve — at least twice (lighttpd and firmware/visiontech)
- [ ] analyze_firmware_config — on the /config response body

## Rules
- You MUST complete ALL four phases before writing the final report. Do not stop early.
- Phase 3 is mandatory even if Phase 2 already found credentials.
- Correlate findings: credentials found in /logs or /debug must be tested at /auth/login.
- If an endpoint returns 401, try auth bypass or use credentials discovered elsewhere.
- Only write the final report after the mandatory tool checklist is fully satisfied.

## Final Report Format
When all phases are done, produce a report in this exact structure:

# IoT Security Assessment Report

## Executive Summary
[2-3 sentence overview of findings]

## Vulnerability Findings

### [VULN-001] [Title] — Severity: CRITICAL/HIGH/MEDIUM/LOW
- **Type**: [CWE or category]
- **Location**: [endpoint/component]
- **Evidence**: [what you observed]
- **Impact**: [what an attacker could do]
- **Remediation**: [how to fix it]

[repeat for each finding]

## Attack Scenario
[Describe a realistic end-to-end attack chain using the vulnerabilities found]

## Risk Summary Table
| ID | Vulnerability | Severity | Location |
|----|--------------|----------|----------|
...

## Recommendations
[Prioritized list of fixes]
"""

# -------------------------------------------------------
# Phase completion tracker
# -------------------------------------------------------
REQUIRED_TOOLS = {
    "probe_endpoint",
    "analyze_headers",
    "test_credentials",
    "test_auth_bypass",
    "scan_for_secrets",
    "lookup_cve",
    "analyze_firmware_config",
}

# -------------------------------------------------------
# Logger
# -------------------------------------------------------
interaction_log = []

def log(entry: dict):
    entry["timestamp"] = datetime.now().isoformat()
    interaction_log.append(entry)
    print(f"\n{'='*60}")
    print(f"[{entry['timestamp']}] {entry.get('type','').upper()}")
    if "tool" in entry:
        print(f"  Tool: {entry['tool']}")
        print(f"  Input: {json.dumps(entry.get('input', {}), indent=2)[:300]}")
    if "content" in entry:
        print(f"  {str(entry['content'])[:400]}")
    if "result" in entry:
        print(f"  Result: {json.dumps(entry['result'], indent=2)[:500]}")

def save_logs():
    with open(log_path, "w") as f:
        json.dump(interaction_log, f, indent=2, default=str)
    print(f"\n[*] Interaction log saved: {log_path}")

# -------------------------------------------------------
# Agent loop
# -------------------------------------------------------
def run_agent():
    print("\n" + "="*60)
    print("  IoT SECURITY AGENT — ECE202C")
    print("  Model: gpt-4o-mini")
    print("  Target: http://127.0.0.1:5000")
    print("="*60)

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                "Begin the security assessment of the IoT camera at http://127.0.0.1:5000. "
                "Follow your phased investigation strategy. Start with Phase 1 reconnaissance."
            ),
        },
    ]

    max_iterations = 30
    iteration = 0
    tools_used = set()

    log({"type": "start", "content": "Agent started"})

    while iteration < max_iterations:
        iteration += 1
        log({"type": "iteration", "content": f"Iteration {iteration}/{max_iterations}"})

        # Call the model
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            max_tokens=4096,
            tools=TOOL_SCHEMAS,
            tool_choice="auto",
            messages=messages,
        )

        msg = response.choices[0].message
        finish_reason = response.choices[0].finish_reason

        log({"type": "llm_response", "content": f"finish_reason={finish_reason}"})

        # Add assistant reply to history
        messages.append(msg)

        # ── Model wants to stop ───────────────────────────────
        if finish_reason == "stop":
            final_text = msg.content or ""

            # Check if it stopped before finishing all phases
            missing_tools = REQUIRED_TOOLS - tools_used
            report_written = "# IoT Security Assessment Report" in final_text

            if not report_written or missing_tools:
                missing_list = ", ".join(missing_tools) if missing_tools else "none"
                log({"type": "nudge", "content": f"Early stop detected. Missing tools: {missing_list}"})
                print(f"\n[!] Agent stopped early. Missing tools: {missing_list}. Nudging to continue...")
                messages.append({
                    "role": "user",
                    "content": (
                        f"You stopped before completing all required phases. "
                        f"You have NOT yet called these mandatory tools: {missing_list}. "
                        "You must complete Phase 3 before writing the final report: "
                        "call lookup_cve on lighttpd and visiontech versions, "
                        "call scan_for_secrets on /debug and /logs response bodies, "
                        "and call analyze_firmware_config on the /config response. "
                        "Continue the investigation now — do not write the report until all tools have been used."
                    ),
                })
                continue  # re-enter the loop

            # Genuine completion
            log({"type": "final_report", "content": final_text})
            print("\n" + "="*60)
            print("FINAL SECURITY REPORT")
            print("="*60)
            print(final_text)
            with open(report_path, "w") as f:
                f.write(final_text)
            print(f"\n[*] Report saved: {report_path}")
            break

        # ── Tool calls requested ──────────────────────────────
        if finish_reason == "tool_calls" and msg.tool_calls:

            if msg.content and msg.content.strip():
                log({"type": "agent_reasoning", "content": msg.content[:600]})

            for tc in msg.tool_calls:
                tool_name = tc.function.name
                tool_id   = tc.id

                try:
                    tool_input = json.loads(tc.function.arguments)
                except json.JSONDecodeError as e:
                    tool_input = {}
                    log({"type": "tool_error", "tool": tool_name,
                         "result": {"error": f"Bad JSON args: {e}"}})

                log({"type": "tool_call", "tool": tool_name, "input": tool_input})
                tools_used.add(tool_name)

                # Execute tool
                if tool_name in TOOLS:
                    try:
                        result = TOOLS[tool_name](**tool_input)
                        log({"type": "tool_result", "tool": tool_name, "result": result})
                    except Exception as e:
                        result = {"error": str(e), "traceback": traceback.format_exc()[:500]}
                        log({"type": "tool_error", "tool": tool_name, "result": result})
                else:
                    result = {"error": f"Unknown tool: {tool_name}"}
                    log({"type": "tool_error", "tool": tool_name, "result": result})

                # Feed result back as a tool message
                messages.append({
                    "role":         "tool",
                    "tool_call_id": tool_id,
                    "content":      json.dumps(result, default=str),
                })

        time.sleep(0.2)

    else:
        print("\n[!] Max iterations reached without final report")
        log({"type": "warning", "content": "Max iterations reached"})

    save_logs()
    return report_path, log_path


if __name__ == "__main__":
    report, lg = run_agent()
    print(f"\nDone. Report: {report} | Log: {lg}")