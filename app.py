"""
Simulated Vulnerable IoT Smart Camera
ECE202C - Spring 26 | Security Research Target

Intentional vulnerabilities for research purposes:
  - CVE-class: Auth bypass, info disclosure, command injection surface,
    default credentials, insecure direct object reference, debug exposure
"""

from flask import Flask, request, jsonify, Response
import hashlib
import base64
import json
import time
import random

app = Flask(__name__)

# -------------------------------------------------------
# "Hidden" device config (realistic embedded device sim)
# -------------------------------------------------------
DEVICE_CONFIG = {
    "model": "SmartEye-Pro-v2",
    "firmware": "2.1.4",
    "manufacturer": "VisionTech",
    "build_date": "2022-03-15",
    "debug_mode": True,           # VULN: debug left on in production
    "telnet_enabled": True,       # VULN: legacy protocol enabled
    "default_creds_changed": False,
}

# VULN: Hardcoded credentials (common in IoT firmware)
USERS = {
    "admin": "admin123",          # default never changed
    "guest": "guest",
    "service": "Visio2022!",      # backdoor service account
}

# VULN: API tokens stored in plaintext
API_TOKENS = {
    "mobile_app":  "tok_8f3a2b1c9d4e5f6a",
    "cloud_sync":  "tok_7e6d5c4b3a2f1e0d",
    "debug_token": "tok_deadbeefcafebabe",  # VULN: predictable debug token
}

# In-memory "session" store (no expiry = VULN)
active_sessions = {}

# Fake event log
SYSTEM_LOG = [
    {"ts": "2024-01-10 08:00:01", "event": "BOOT",    "user": "system",  "detail": "Device started"},
    {"ts": "2024-01-10 08:00:05", "event": "LOGIN",   "user": "admin",   "detail": "Login from 192.168.1.100"},
    {"ts": "2024-01-10 09:14:22", "event": "CONFIG",  "user": "admin",   "detail": "RTSP stream enabled"},
    {"ts": "2024-01-10 11:30:00", "event": "LOGIN",   "user": "service", "detail": "Login from 10.0.0.2"},
    {"ts": "2024-01-10 14:55:10", "event": "UPLOAD",  "user": "admin",   "detail": "Firmware update skipped (unsigned)"},
    {"ts": "2024-01-10 16:00:00", "event": "ACCESS",  "user": "guest",   "detail": "Viewed /stream endpoint"},
]


# -------------------------------------------------------
# Helper: Weak auth check (base64, no rate limiting)
# -------------------------------------------------------
def check_auth(req):
    """VULN: Basic auth with no brute-force protection"""
    auth = req.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            username, password = decoded.split(":", 1)
            if username in USERS and USERS[username] == password:
                return username
        except Exception:
            pass
    # VULN: Also accepts token in query param (bad practice)
    token = req.args.get("token", "")
    if token in API_TOKENS.values():
        return "token_user"
    return None


# -------------------------------------------------------
# Routes
# -------------------------------------------------------

@app.route("/")
def index():
    """Public landing — leaks model/firmware info in headers"""
    resp = Response(json.dumps({
        "device": DEVICE_CONFIG["model"],
        "status": "online",
        "uptime_seconds": int(time.time()) % 86400,
    }), mimetype="application/json")
    # VULN: Version disclosure in headers
    resp.headers["X-Device-Model"]    = DEVICE_CONFIG["model"]
    resp.headers["X-Firmware-Version"] = DEVICE_CONFIG["firmware"]
    resp.headers["X-Manufacturer"]    = DEVICE_CONFIG["manufacturer"]
    resp.headers["Server"]            = "lighttpd/1.4.45"   # VULN: old server version
    return resp


@app.route("/status")
def status():
    """Device status — no auth required (VULN: sensitive info public)"""
    return jsonify({
        "device":        DEVICE_CONFIG["model"],
        "firmware":      DEVICE_CONFIG["firmware"],
        "status":        "active",
        "debug_mode":    DEVICE_CONFIG["debug_mode"],
        "telnet":        DEVICE_CONFIG["telnet_enabled"],
        "temperature":   f"{random.randint(68, 78)}F",
        "ip_internal":   "192.168.1.105",        # VULN: internal IP leaked
        "mac":           "AA:BB:CC:DD:EE:FF",
        "open_ports":    [80, 23, 554, 8080],    # VULN: telnet port 23 visible
        "cloud_endpoint": "http://cloud.visiontech-iot.com/api/v1",
    })


@app.route("/auth/login", methods=["POST"])
def login():
    """Login endpoint — no rate limiting, verbose errors"""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if username in USERS:
        if USERS[username] == password:
            token = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()  # VULN: MD5 session token
            active_sessions[token] = username
            return jsonify({"status": "ok", "token": token, "role": "admin" if username == "admin" else "user"})
        else:
            # VULN: Reveals that username EXISTS (user enumeration)
            return jsonify({"status": "error", "message": f"Wrong password for user '{username}'"}), 401
    return jsonify({"status": "error", "message": "User not found"}), 404


@app.route("/stream")
def stream():
    """RTSP stream config — no auth, leaks stream URI with credentials"""
    # VULN: No authentication on stream endpoint
    return jsonify({
        "rtsp_url":   "rtsp://admin:admin123@192.168.1.105:554/live",   # VULN: creds in URL
        "resolution": "1080p",
        "fps":        30,
        "codec":      "H.264",
        "recording":  True,
        "storage":    "/mnt/sdcard/recordings",
    })


@app.route("/config")
def config():
    """Full device config — requires auth, but guest works"""
    user = check_auth(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "network": {
            "ssid":     "HomeNetwork",
            "wifi_key": "supersecret123",       # VULN: WiFi password stored plaintext
            "dhcp":     True,
            "dns":      "8.8.8.8",
        },
        "cloud": {
            "enabled":    True,
            "api_key":    API_TOKENS["cloud_sync"],   # VULN: API key in response
            "endpoint":   "http://cloud.visiontech-iot.com/api/v1",
            "tls_verify": False,                # VULN: TLS verification disabled
        },
        "firmware": {
            "auto_update":   False,
            "update_server": "http://update.visiontech-iot.com",  # VULN: HTTP not HTTPS
            "signed_only":   False,             # VULN: accepts unsigned firmware
        },
    })


@app.route("/logs")
def logs():
    """System logs — requires auth, but reveals too much"""
    user = check_auth(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # VULN: Logs contain credentials and session data
    return jsonify({
        "entries": SYSTEM_LOG,
        "active_sessions": active_sessions,     # VULN: live session tokens leaked
        "stored_credentials": USERS,            # VULN: all passwords in logs
    })


@app.route("/debug")
def debug():
    """Debug endpoint — should be disabled in production"""
    # VULN: No auth on debug endpoint
    if not DEVICE_CONFIG["debug_mode"]:
        return jsonify({"error": "Debug disabled"}), 403

    cmd = request.args.get("cmd", "")
    # VULN: Command injection surface (simulated — not actually executed)
    result = f"[SIMULATED] Would execute: `{cmd}`" if cmd else "Debug console ready"

    return jsonify({
        "debug":        True,
        "env": {
            "PATH":         "/usr/bin:/bin",
            "HOME":         "/root",
            "MQTT_BROKER":  "mqtt://broker.visiontech-iot.com:1883",
            "MQTT_USER":    "camera_105",
            "MQTT_PASS":    "Mqtt@2022",         # VULN: MQTT creds in env
            "SECRET_KEY":   "dev-secret-do-not-use",
        },
        "cmd_result":   result,
        "users":        USERS,                  # VULN: creds again in debug
    })


@app.route("/firmware/update", methods=["POST"])
def firmware_update():
    """Firmware update — accepts unsigned packages over HTTP"""
    # VULN: No signature verification, no auth check on method
    user = check_auth(request)
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "")

    return jsonify({
        "status":   "accepted",
        "url":      url,
        "signed":   False,   # VULN: would install without checking signature
        "warning":  "Signature verification is disabled",
    })


@app.route("/api/users")
def list_users():
    """VULN: IDOR — lists all users with hashed(ish) passwords"""
    user = check_auth(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    # VULN: Returns all user data including passwords
    return jsonify({u: {"password": p, "hash": hashlib.md5(p.encode()).hexdigest()} for u, p in USERS.items()})


if __name__ == "__main__":
    print("[*] Simulated IoT Camera running on http://127.0.0.1:5000")
    print("[*] Intentional vulnerabilities active for research")
    app.run(port=5000, debug=False)
