"""
Security Analysis Tools for IoT Agent
ECE202C - Spring 26

Each tool is a standalone function the agent can call.
Tools simulate what a real pentester would do manually.
"""

import requests
import json
import base64
import socket
import hashlib
from urllib.parse import urljoin


TARGET = "http://127.0.0.1:5000"


# -------------------------------------------------------
# Tool: HTTP Probe
# -------------------------------------------------------
def probe_endpoint(endpoint: str, method: str = "GET",
                   headers: dict = None, body: dict = None,
                   auth: tuple = None) -> dict:
    """
    Fetch an endpoint and return status, headers, and body.
    Also checks for common security header presence/absence.
    """
    url = urljoin(TARGET, endpoint)
    kwargs = {"timeout": 5, "headers": headers or {}}
    if auth:
        raw = f"{auth[0]}:{auth[1]}"
        b64 = base64.b64encode(raw.encode()).decode()
        kwargs["headers"]["Authorization"] = f"Basic {b64}"
    if body:
        kwargs["json"] = body
        kwargs["headers"]["Content-Type"] = "application/json"

    try:
        r = getattr(requests, method.lower())(url, **kwargs)
        security_headers = {
            "X-Frame-Options":           r.headers.get("X-Frame-Options", "MISSING"),
            "X-Content-Type-Options":    r.headers.get("X-Content-Type-Options", "MISSING"),
            "Strict-Transport-Security": r.headers.get("Strict-Transport-Security", "MISSING"),
            "Content-Security-Policy":   r.headers.get("Content-Security-Policy", "MISSING"),
        }
        return {
            "url":              url,
            "status":           r.status_code,
            "response_headers": dict(r.headers),
            "security_headers": security_headers,
            "body":             r.text[:4000],
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


# -------------------------------------------------------
# Tool: Header Analyzer
# -------------------------------------------------------
def analyze_headers(response_headers: dict) -> dict:
    """
    Inspect HTTP response headers for security misconfigs
    and information disclosure.
    """
    findings = []
    info_disclosure = []

    disclosure_keys = ["Server", "X-Powered-By", "X-Device-Model",
                       "X-Firmware-Version", "X-Manufacturer", "X-AspNet-Version"]
    for key in disclosure_keys:
        if key in response_headers:
            info_disclosure.append({
                "header": key,
                "value":  response_headers[key],
                "risk":   "INFO_DISCLOSURE"
            })
            findings.append(f"Header '{key}' reveals: {response_headers[key]}")

    missing_security = ["X-Frame-Options", "X-Content-Type-Options",
                        "Strict-Transport-Security", "Content-Security-Policy"]
    for h in missing_security:
        if h not in response_headers:
            findings.append(f"Missing security header: {h}")

    return {
        "info_disclosure":   info_disclosure,
        "missing_headers":   [h for h in missing_security if h not in response_headers],
        "findings_summary":  findings,
    }


# -------------------------------------------------------
# Tool: Credential Tester
# -------------------------------------------------------
def test_credentials(endpoint: str, credentials_list: list) -> dict:
    """
    Try a list of (username, password) pairs against an endpoint.
    Detects: successful logins, user enumeration via error messages.
    """
    results = []
    user_enumeration_detected = False

    for username, password in credentials_list:
        try:
            r = requests.post(
                urljoin(TARGET, endpoint),
                json={"username": username, "password": password},
                timeout=5
            )
            body = {}
            try:
                body = r.json()
            except Exception:
                pass

            result = {
                "username":  username,
                "password":  password,
                "status":    r.status_code,
                "response":  body,
                "success":   r.status_code == 200,
            }

            # Detect user enumeration: different error for valid vs invalid username
            msg = str(body.get("message", "")).lower()
            if "wrong password" in msg or f"user '{username}'" in msg:
                user_enumeration_detected = True
                result["user_enumeration"] = True

            results.append(result)
        except Exception as e:
            results.append({"username": username, "error": str(e)})

    successful = [r for r in results if r.get("success")]
    return {
        "tested_count":              len(results),
        "successful_logins":         successful,
        "user_enumeration_detected": user_enumeration_detected,
        "all_results":               results,
    }


# -------------------------------------------------------
# Tool: Token / Secret Scanner
# -------------------------------------------------------
def scan_for_secrets(text: str) -> dict:
    """
    Scan a response body for secrets: API keys, tokens,
    passwords, private IPs, credentials in URLs.
    """
    import re

    patterns = {
        "api_token":       r'tok_[a-f0-9]{16,}',
        "md5_hash":        r'\b[a-f0-9]{32}\b',
        "basic_auth_url":  r'[a-zA-Z]+://[^:]+:[^@]+@',
        "private_ipv4":    r'192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',
        "mqtt_url":        r'mqtt://[^\s"\']+',
        "password_field":  r'"password"\s*:\s*"[^"]+"',
        "wifi_key":        r'"wifi_key"\s*:\s*"[^"]+"',
        "secret_key":      r'"[Ss][Ee][Cc][Rr][Ee][Tt][_-]?[Kk][Ee][Yy]"\s*:\s*"[^"]+"',
    }

    found = {}
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            found[name] = list(set(matches))

    risk_level = "LOW"
    if any(k in found for k in ["api_token", "password_field", "basic_auth_url"]):
        risk_level = "CRITICAL"
    elif any(k in found for k in ["mqtt_url", "wifi_key", "secret_key"]):
        risk_level = "HIGH"
    elif found:
        risk_level = "MEDIUM"

    return {
        "secrets_found": found,
        "total_matches": sum(len(v) for v in found.values()),
        "risk_level":    risk_level,
    }


# -------------------------------------------------------
# Tool: Auth Bypass Tester
# -------------------------------------------------------
def test_auth_bypass(endpoint: str) -> dict:
    """
    Try common auth bypass techniques:
    - No auth
    - Token in query param
    - Predictable tokens
    - Guest credentials
    """
    bypass_attempts = [
        {"label": "no_auth",          "headers": {},                                          "params": {}},
        {"label": "debug_token_param","headers": {},                                          "params": {"token": "tok_deadbeefcafebabe"}},
        {"label": "generic_token",    "headers": {"Authorization": "Bearer admin"},           "params": {}},
        {"label": "guest_basic",      "headers": {},                                          "params": {},
         "auth": ("guest", "guest")},
    ]

    results = []
    for attempt in bypass_attempts:
        hdrs = attempt["headers"].copy()
        if "auth" in attempt:
            u, p = attempt["auth"]
            hdrs["Authorization"] = "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()
        try:
            r = requests.get(
                urljoin(TARGET, endpoint),
                headers=hdrs,
                params=attempt["params"],
                timeout=5
            )
            results.append({
                "method":  attempt["label"],
                "status":  r.status_code,
                "success": r.status_code == 200,
                "body":    r.text[:500],
            })
        except Exception as e:
            results.append({"method": attempt["label"], "error": str(e)})

    bypassed = [r for r in results if r.get("success")]
    return {
        "endpoint":        endpoint,
        "bypass_found":    len(bypassed) > 0,
        "bypasses":        bypassed,
        "all_attempts":    results,
    }


# -------------------------------------------------------
# Tool: CVE Lookup (simulated local DB)
# -------------------------------------------------------
def lookup_cve(component: str, version: str) -> dict:
    """
    Match component/version against a local simulated CVE database.
    In a real agent this would hit NVD or Shodan.
    """
    CVE_DB = {
        ("lighttpd", "1.4.45"): [
            {"id": "CVE-2022-22707", "severity": "HIGH",
             "desc": "lighttpd 1.4.45 mod_extforward heap use-after-free"},
        ],
        ("visiontech", "2.1.4"): [
            {"id": "CVE-2023-SIMULATED-001", "severity": "CRITICAL",
             "desc": "VisionTech firmware 2.x default credentials never rotated"},
            {"id": "CVE-2023-SIMULATED-002", "severity": "HIGH",
             "desc": "VisionTech debug endpoint exposed in production firmware"},
        ],
        ("mqtt", "1883"): [
            {"id": "CVE-2022-MQTT-UNAUTH", "severity": "HIGH",
             "desc": "Unencrypted MQTT on port 1883 with credentials in plaintext"},
        ],
    }

    key_lower = component.lower()
    ver_lower  = version.lower()
    matches = []
    for (comp, ver), cves in CVE_DB.items():
        if comp in key_lower or key_lower in comp:
            if ver in ver_lower or ver_lower in ver or ver == "*":
                matches.extend(cves)

    return {
        "component": component,
        "version":   version,
        "cves_found": matches,
        "total":     len(matches),
    }


# -------------------------------------------------------
# Tool: Firmware Risk Analyzer
# -------------------------------------------------------
def analyze_firmware_config(config_data: dict) -> dict:
    """
    Inspect a firmware/device config blob for security issues.
    """
    risks = []
    score = 0

    def check(condition, severity, finding):
        nonlocal score
        if condition:
            risks.append({"severity": severity, "finding": finding})
            score += {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}.get(severity, 0)

    fw = config_data.get("firmware", {})
    net = config_data.get("network", {})
    cloud = config_data.get("cloud", {})

    check(fw.get("signed_only") is False,       "CRITICAL", "Firmware accepts unsigned updates — allows arbitrary code execution")
    check(fw.get("auto_update") is False,        "MEDIUM",   "Auto-updates disabled — device won't receive security patches")
    check(fw.get("update_server", "").startswith("http://"), "HIGH", "Firmware update over HTTP — susceptible to MITM/downgrade attack")
    check(cloud.get("tls_verify") is False,      "HIGH",     "TLS certificate verification disabled for cloud connection")
    check("wifi_key" in net,                     "HIGH",     "WiFi pre-shared key stored in plaintext in device config")
    check(cloud.get("api_key"),                  "HIGH",     "Cloud API key stored in device config (no secret manager)")

    risk_level = "LOW"
    if score >= 20:   risk_level = "CRITICAL"
    elif score >= 12: risk_level = "HIGH"
    elif score >= 6:  risk_level = "MEDIUM"

    return {
        "risk_score":  score,
        "risk_level":  risk_level,
        "findings":    risks,
        "total_issues": len(risks),
    }
