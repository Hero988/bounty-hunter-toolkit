#!/usr/bin/env python3
"""
OWASP ZAP Controller for bounty-hunter-toolkit.
Manages ZAP in daemon mode for automated web security scanning.

Controls:
  --start / --stop / --status       ZAP lifecycle
  --spider / --ajax-spider          Crawling
  --active-scan / --full-scan       Vulnerability scanning
  --authenticated-scan              Scan with cookies
  --alerts / --report / --export-alerts  Results
  --set-cookies / --set-header      Authentication helpers
  --proxy-url / --history           Proxy features
  --hunt <scope.json> <output-dir>  Full automated pipeline

Requires: Python 3.8+, zaproxy library (auto-installed).
"""

import argparse
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
HOME = Path.home()
IS_WINDOWS = platform.system().lower() == "windows"
PYTHON_CMD = "python" if IS_WINDOWS else "python3"
DATA_DIR = HOME / ".bounty-hunter-data"
CONFIG_FILE = DATA_DIR / "zap-config.json"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8090
ZAP_DOCKER_IMAGE = "owasp/zap2docker-stable"
POLL_INTERVAL = 5  # seconds between progress polls
SCAN_TIMEOUT = 3600  # max seconds for a single scan phase


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd, timeout=30):
    """Run a shell command and return (success, stdout+stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, (result.stdout or "") + (result.stderr or "")
    except Exception as exc:
        return False, str(exc)


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def error(msg, code=1):
    log(f"ERROR: {msg}")
    sys.exit(code)


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Configuration persistence
# ---------------------------------------------------------------------------

def load_config():
    """Load ZAP config (host, port, api_key, docker flag) from disk."""
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def save_config(cfg):
    ensure_data_dir()
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def get_api_key(cfg):
    """Return existing key or generate a fresh one."""
    key = cfg.get("api_key")
    if not key:
        key = secrets.token_hex(16)
        cfg["api_key"] = key
        save_config(cfg)
    return key


# ---------------------------------------------------------------------------
# ZAP installation detection
# ---------------------------------------------------------------------------

def _check_path(name):
    return shutil.which(name)


def find_zap_binary():
    """Return the path to the ZAP start script, or None."""
    # 1) Check PATH
    for name in ("zap.sh", "zap.bat", "zaproxy"):
        p = _check_path(name)
        if p:
            return p

    # 2) Common install locations
    candidates = []
    if IS_WINDOWS:
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        for base in (pf, pf86):
            candidates.append(Path(base) / "OWASP" / "Zed Attack Proxy" / "zap.bat")
            candidates.append(Path(base) / "ZAP" / "zap.bat")
        candidates.append(HOME / "AppData" / "Local" / "Programs" / "ZAP" / "zap.bat")
    else:
        candidates += [
            Path("/opt/zaproxy/zap.sh"),
            Path("/usr/share/zaproxy/zap.sh"),
            Path("/usr/local/bin/zap.sh"),
            Path("/snap/zaproxy/current/zap.sh"),
            HOME / "ZAP" / "zap.sh",
            HOME / ".ZAP" / "zap.sh",
        ]
        if platform.system().lower() == "darwin":
            candidates.append(
                Path("/Applications/OWASP ZAP.app/Contents/Java/zap.sh")
            )

    for c in candidates:
        if c.exists():
            return str(c)

    return None


def docker_available():
    ok, _ = run_cmd("docker version", timeout=10)
    return ok


# ---------------------------------------------------------------------------
# zaproxy library (auto-install)
# ---------------------------------------------------------------------------

def ensure_zaplib():
    """Import the ZAPv2 client, installing via pip if absent."""
    try:
        from zapv2 import ZAPv2
        return ZAPv2
    except ImportError:
        pass
    log("zaproxy library not found -- installing via pip ...")
    ok, out = run_cmd(f"{PYTHON_CMD} -m pip install zaproxy --quiet", timeout=120)
    if not ok:
        error(f"Failed to install zaproxy library:\n{out}")
    try:
        from zapv2 import ZAPv2
        return ZAPv2
    except ImportError:
        error("zaproxy installed but cannot import ZAPv2. Check your Python environment.")


# ---------------------------------------------------------------------------
# ZAP lifecycle
# ---------------------------------------------------------------------------

def _port_open(host, port, timeout=2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def zap_running(host=DEFAULT_HOST, port=DEFAULT_PORT):
    return _port_open(host, port)


def start_zap(host, port, cfg):
    """Start ZAP in daemon mode. Returns updated config."""
    if zap_running(host, port):
        log(f"ZAP already running on {host}:{port}")
        return cfg

    api_key = get_api_key(cfg)
    zap_bin = find_zap_binary()

    if zap_bin:
        cmd = (
            f'"{zap_bin}" -daemon -host {host} -port {port}'
            f" -config api.key={api_key}"
            f" -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"
        )
        log(f"Starting ZAP: {cmd}")
        subprocess.Popen(
            cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        cfg["mode"] = "local"
    elif docker_available():
        log("ZAP binary not found -- using Docker image")
        cmd = (
            f"docker run -d --name zap-daemon -p {port}:{port}"
            f" {ZAP_DOCKER_IMAGE}"
            f" zap.sh -daemon -host 0.0.0.0 -port {port}"
            f" -config api.key={api_key}"
            f" -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true"
        )
        log(cmd)
        ok, out = run_cmd(cmd, timeout=60)
        if not ok:
            # Container name may already exist; try removing then rerunning
            run_cmd("docker rm -f zap-daemon", timeout=10)
            ok, out = run_cmd(cmd, timeout=60)
            if not ok:
                error(f"Docker start failed:\n{out}")
        cfg["mode"] = "docker"
    else:
        error(
            "ZAP not found and Docker not available.\n"
            "Install ZAP: https://www.zaproxy.org/download/\n"
            "Or install Docker and run: docker pull owasp/zap2docker-stable"
        )

    cfg["host"] = host
    cfg["port"] = port
    save_config(cfg)

    # Wait for ZAP to be ready
    log("Waiting for ZAP to initialize ...")
    for i in range(60):
        if zap_running(host, port):
            log("ZAP is ready")
            return cfg
        time.sleep(2)

    error("ZAP did not start within 120 seconds")


def stop_zap(cfg):
    """Gracefully shut down ZAP."""
    host = cfg.get("host", DEFAULT_HOST)
    port = cfg.get("port", DEFAULT_PORT)

    if not zap_running(host, port):
        log("ZAP is not running")
        return

    ZAPv2 = ensure_zaplib()
    zap = ZAPv2(
        apikey=cfg.get("api_key", ""),
        proxies={"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"},
    )
    try:
        log("Sending shutdown command ...")
        zap.core.shutdown()
    except Exception:
        pass

    # If running via Docker, also stop the container
    if cfg.get("mode") == "docker":
        run_cmd("docker stop zap-daemon && docker rm zap-daemon", timeout=30)

    # Wait for port to close
    for _ in range(15):
        if not zap_running(host, port):
            log("ZAP stopped")
            return
        time.sleep(1)

    log("ZAP may still be shutting down; port still open after 15 s")


def status_zap(cfg):
    host = cfg.get("host", DEFAULT_HOST)
    port = cfg.get("port", DEFAULT_PORT)
    if zap_running(host, port):
        log(f"ZAP is RUNNING on {host}:{port}  (mode={cfg.get('mode','unknown')})")
    else:
        log(f"ZAP is NOT running (expected {host}:{port})")


# ---------------------------------------------------------------------------
# Connect to running ZAP
# ---------------------------------------------------------------------------

def connect_zap(cfg):
    """Return a ZAPv2 client connected to the running daemon."""
    host = cfg.get("host", DEFAULT_HOST)
    port = cfg.get("port", DEFAULT_PORT)
    if not zap_running(host, port):
        error(f"ZAP is not running on {host}:{port}.  Use --start first.")
    ZAPv2 = ensure_zaplib()
    return ZAPv2(
        apikey=cfg.get("api_key", ""),
        proxies={"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"},
    )


# ---------------------------------------------------------------------------
# Cookie / header helpers
# ---------------------------------------------------------------------------

def load_cookies_file(path):
    """Parse cookies from our auth_manager.py outputs (JSON or Netscape txt)."""
    path = Path(path)
    if not path.exists():
        error(f"Cookie file not found: {path}")

    text = path.read_text(encoding="utf-8", errors="replace")

    # Try JSON first
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data  # already a list of cookie dicts
        if isinstance(data, dict) and "cookies" in data:
            return data["cookies"]
        return [data]
    except (json.JSONDecodeError, ValueError):
        pass

    # Netscape cookie.txt format
    cookies = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            cookies.append({
                "domain": parts[0],
                "path": parts[2],
                "secure": parts[3].upper() == "TRUE",
                "name": parts[5],
                "value": parts[6],
            })
    if cookies:
        return cookies

    error(f"Cannot parse cookie file: {path}")


def set_cookies(zap, domain, cookie_list):
    """Inject cookies into ZAP's HTTP session for *domain*."""
    count = 0
    for c in cookie_list:
        name = c.get("name", "")
        value = c.get("value", "")
        cdomain = c.get("domain", domain)
        cpath = c.get("path", "/")
        secure = c.get("secure", False)
        if not name:
            continue
        try:
            zap.httpsessions.set_session_token_value(
                site=domain, session="default",
                sessiontoken=name, tokenvalue=value,
            )
        except Exception:
            # Fallback: add as a replacer rule (header cookie)
            pass
        count += 1

    # Also set a Cookie header via replacer so all requests carry it
    cookie_header = "; ".join(
        f'{c["name"]}={c["value"]}' for c in cookie_list if c.get("name")
    )
    if cookie_header:
        try:
            zap.replacer.add_rule(
                description="auth-cookies",
                enabled="true",
                matchtype="REQ_HEADER",
                matchregex="false",
                matchstring="Cookie",
                replacement=cookie_header,
                initiators="",
            )
        except Exception:
            pass

    log(f"Loaded {count} cookies for {domain}")


def set_header(zap, name, value):
    """Add a custom request header via ZAP Replacer."""
    try:
        zap.replacer.add_rule(
            description=f"custom-header-{name}",
            enabled="true",
            matchtype="REQ_HEADER",
            matchregex="false",
            matchstring=name,
            replacement=value,
            initiators="",
        )
        log(f"Header set: {name}")
    except Exception as exc:
        error(f"Failed to set header: {exc}")


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _wait_scan(zap, scan_id, scan_type_obj, label, timeout=SCAN_TIMEOUT):
    """Poll a ZAP scan until completion, printing progress."""
    start = time.time()
    last_pct = -1
    while True:
        try:
            pct = int(scan_type_obj.status(scan_id))
        except Exception:
            pct = -1

        if pct != last_pct:
            log(f"{label} progress: {pct}%")
            last_pct = pct

        if pct >= 100:
            log(f"{label} complete")
            return True

        if time.time() - start > timeout:
            log(f"{label} timed out after {timeout}s")
            return False

        time.sleep(POLL_INTERVAL)


def spider_url(zap, url, as_user=False):
    """Run the traditional spider on *url*."""
    log(f"Spidering {url} ...")
    scan_id = zap.spider.scan(url)
    return _wait_scan(zap, scan_id, zap.spider, "Spider")


def ajax_spider_url(zap, url):
    """Run the AJAX spider on *url* (for JS-heavy sites)."""
    log(f"AJAX-spidering {url} ...")
    zap.ajaxSpider.scan(url)
    start = time.time()
    while True:
        status = zap.ajaxSpider.status
        if status == "stopped":
            log("AJAX spider complete")
            return True
        results = int(zap.ajaxSpider.number_of_results)
        log(f"AJAX spider running ... {results} results found so far")
        if time.time() - start > SCAN_TIMEOUT:
            zap.ajaxSpider.stop()
            log("AJAX spider timed out")
            return False
        time.sleep(POLL_INTERVAL)


def active_scan_url(zap, url):
    """Run an active scan on *url* (must be spidered first)."""
    log(f"Active scanning {url} ...")
    scan_id = zap.ascan.scan(url)
    return _wait_scan(zap, scan_id, zap.ascan, "Active scan")


def full_scan_url(zap, url):
    """Spider then active-scan a URL."""
    spider_url(zap, url)
    ajax_spider_url(zap, url)
    active_scan_url(zap, url)


# ---------------------------------------------------------------------------
# Alerts / results
# ---------------------------------------------------------------------------

RISK_MAP = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}


def get_alerts(zap, base_url=None, risk_filter=None):
    """Return deduplicated alert list, optionally filtered by risk."""
    if base_url:
        raw = zap.core.alerts(baseurl=base_url)
    else:
        raw = zap.core.alerts()

    # Deduplicate by (pluginid, url, param)
    seen = set()
    alerts = []
    for a in raw:
        key = (a.get("pluginId"), a.get("url"), a.get("param", ""))
        if key in seen:
            continue
        seen.add(key)

        if risk_filter:
            if a.get("risk", "").lower() not in [r.lower() for r in risk_filter]:
                continue
        alerts.append(a)

    return alerts


def print_alerts(alerts):
    """Pretty-print alerts to stdout."""
    if not alerts:
        log("No alerts found")
        return
    log(f"Found {len(alerts)} unique alert(s):")
    for a in sorted(alerts, key=lambda x: -RISK_MAP.get(x.get("risk", ""), -1)):
        risk = a.get("risk", "?")
        name = a.get("alert", a.get("name", "?"))
        url = a.get("url", "?")
        confidence = a.get("confidence", "?")
        print(f"  [{risk}] {name}")
        print(f"       URL: {url}")
        print(f"       Confidence: {confidence}")
        if a.get("param"):
            print(f"       Param: {a['param']}")
        print()


def export_alerts_json(alerts, output_path):
    """Write alerts to a JSON file."""
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    log(f"Exported {len(alerts)} alerts to {output_path}")


def generate_report(zap, output_dir, fmt="json"):
    """Generate a scan report in the requested format."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        path = output_dir / f"zap-report-{ts}.json"
        alerts = get_alerts(zap)
        summary = {
            "generated": ts,
            "total_alerts": len(alerts),
            "by_risk": {},
            "alerts": alerts,
        }
        for a in alerts:
            r = a.get("risk", "Unknown")
            summary["by_risk"][r] = summary["by_risk"].get(r, 0) + 1
        path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        log(f"JSON report saved: {path}")
        return str(path)

    elif fmt == "html":
        path = output_dir / f"zap-report-{ts}.html"
        try:
            html = zap.core.htmlreport()
            path.write_text(html, encoding="utf-8")
            log(f"HTML report saved: {path}")
            return str(path)
        except Exception as exc:
            log(f"HTML report failed ({exc}), falling back to JSON")
            return generate_report(zap, output_dir, "json")

    elif fmt == "md":
        path = output_dir / f"zap-report-{ts}.md"
        alerts = get_alerts(zap)
        lines = [
            f"# ZAP Scan Report  {ts}",
            "",
            f"**Total alerts:** {len(alerts)}",
            "",
        ]
        for risk in ("High", "Medium", "Low", "Informational"):
            group = [a for a in alerts if a.get("risk") == risk]
            if not group:
                continue
            lines.append(f"## {risk} ({len(group)})")
            lines.append("")
            for a in group:
                lines.append(f"### {a.get('alert', '?')}")
                lines.append(f"- **URL:** {a.get('url', '?')}")
                lines.append(f"- **Confidence:** {a.get('confidence', '?')}")
                if a.get("param"):
                    lines.append(f"- **Param:** {a['param']}")
                desc = a.get("description", "")
                if desc:
                    lines.append(f"- **Description:** {desc[:300]}")
                sol = a.get("solution", "")
                if sol:
                    lines.append(f"- **Solution:** {sol[:300]}")
                lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        log(f"Markdown report saved: {path}")
        return str(path)

    else:
        error(f"Unknown report format: {fmt}")


# ---------------------------------------------------------------------------
# Proxy helpers
# ---------------------------------------------------------------------------

def proxy_single_url(zap, url):
    """Send a single GET through the ZAP proxy and print the response."""
    cfg = load_config()
    host = cfg.get("host", DEFAULT_HOST)
    port = cfg.get("port", DEFAULT_PORT)
    proxy_handler = urllib.request.ProxyHandler(
        {"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"}
    )
    opener = urllib.request.build_opener(proxy_handler)
    try:
        resp = opener.open(url, timeout=30)
        body = resp.read().decode("utf-8", errors="replace")
        print(f"Status: {resp.status}")
        print(f"Headers:\n{resp.headers}")
        print(f"Body (first 2000 chars):\n{body[:2000]}")
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code}: {exc.reason}")
    except Exception as exc:
        error(f"Proxy request failed: {exc}")


def show_history(zap, filter_regex=None):
    """Print ZAP proxy history, optionally filtered."""
    try:
        msgs = zap.core.messages()
    except Exception:
        msgs = []

    if filter_regex:
        pat = re.compile(filter_regex, re.IGNORECASE)
        msgs = [m for m in msgs if pat.search(m.get("requestHeader", ""))]

    log(f"Proxy history: {len(msgs)} message(s)")
    for m in msgs[-50:]:  # last 50
        req_line = m.get("requestHeader", "").split("\r\n")[0] if m.get("requestHeader") else "?"
        code = m.get("responseHeader", "").split(" ")[1] if m.get("responseHeader") and " " in m.get("responseHeader", "") else "?"
        ts_msg = m.get("timestamp", "")
        print(f"  [{ts_msg}]  {code}  {req_line}")


# ---------------------------------------------------------------------------
# Full automated hunt
# ---------------------------------------------------------------------------

def hunt(scope_path, output_dir, cfg):
    """
    Full automated scan pipeline driven by scope.json.
    1. Read scope.json
    2. Start ZAP if needed
    3. Load cookies if available
    4. Spider each in-scope URL
    5. Active scan
    6. Export alerts
    7. Generate report
    """
    scope_path = Path(scope_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not scope_path.exists():
        error(f"Scope file not found: {scope_path}")

    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    in_scope = scope.get("in_scope", [])
    if not in_scope:
        error("No in-scope targets found in scope.json")

    # Collect URLs
    urls = []
    for item in in_scope:
        ident = item.get("identifier", "")
        itype = item.get("type", "URL").upper()
        if itype in ("URL", "API", "WILDCARD"):
            # Normalise
            if ident.startswith("*."):
                ident = ident[2:]  # strip wildcard prefix for base domain scan
            if not ident.startswith("http"):
                ident = f"https://{ident}"
            urls.append(ident)

    if not urls:
        error("No scannable URLs extracted from scope.json")

    log(f"Hunt targets ({len(urls)}): {urls}")

    # Step 2 -- ensure ZAP is running
    host = cfg.get("host", DEFAULT_HOST)
    port = cfg.get("port", DEFAULT_PORT)
    if not zap_running(host, port):
        cfg = start_zap(host, port, cfg)

    zap = connect_zap(cfg)

    # Step 3 -- load cookies if available
    auth_dir = scope_path.parent / "auth"
    cookie_candidates = [
        auth_dir / "cookies.json",
        auth_dir / "cookies.txt",
        scope_path.parent / "cookies.json",
        scope_path.parent / "cookies.txt",
    ]
    for cp in cookie_candidates:
        if cp.exists():
            log(f"Loading cookies from {cp}")
            cookie_list = load_cookies_file(cp)
            for url in urls:
                domain = urlparse(url).hostname or ""
                set_cookies(zap, domain, cookie_list)
            break

    # Step 4 & 5 -- spider + active scan each URL
    for url in urls:
        log(f"--- Scanning target: {url} ---")
        spider_url(zap, url)
        ajax_spider_url(zap, url)
        active_scan_url(zap, url)

    # Step 6 -- export alerts
    all_alerts = get_alerts(zap)
    alerts_path = output_dir / "zap-alerts.json"
    export_alerts_json(all_alerts, alerts_path)

    # Step 7 -- generate reports
    generate_report(zap, output_dir, "json")
    generate_report(zap, output_dir, "html")

    # Summary
    high = sum(1 for a in all_alerts if a.get("risk") == "High")
    med = sum(1 for a in all_alerts if a.get("risk") == "Medium")
    low = sum(1 for a in all_alerts if a.get("risk") == "Low")
    info = sum(1 for a in all_alerts if a.get("risk") == "Informational")
    log(
        f"Hunt complete. Alerts: {high} High, {med} Medium, {low} Low, "
        f"{info} Informational.  Results in {output_dir}"
    )
    return all_alerts


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="zap_controller.py",
        description="OWASP ZAP controller for bounty-hunter-toolkit",
    )

    # Lifecycle
    p.add_argument("--start", action="store_true", help="Start ZAP in daemon mode")
    p.add_argument("--stop", action="store_true", help="Gracefully stop ZAP")
    p.add_argument("--status", action="store_true", help="Check if ZAP is running")
    p.add_argument("--port", type=int, default=None, help="ZAP port (default 8090)")
    p.add_argument("--host", default=None, help="ZAP host (default 127.0.0.1)")

    # Scanning
    p.add_argument("--spider", metavar="URL", help="Spider/crawl a target URL")
    p.add_argument("--ajax-spider", metavar="URL", help="AJAX spider for JS-heavy sites")
    p.add_argument("--active-scan", metavar="URL", help="Run active vulnerability scan")
    p.add_argument("--full-scan", metavar="URL", help="Spider + active scan combined")
    p.add_argument(
        "--authenticated-scan", metavar="URL",
        help="Full scan with authentication cookies",
    )
    p.add_argument("--cookies", metavar="FILE", help="Cookie file for authenticated scan")

    # Results
    p.add_argument(
        "--alerts", nargs="?", const="__all__", metavar="URL",
        help="Show alerts (optionally for a specific URL)",
    )
    p.add_argument("--risk", metavar="LEVELS", help="Filter alerts by risk: high,medium,low,informational")
    p.add_argument("--report", metavar="DIR", help="Generate scan report to directory")
    p.add_argument("--format", choices=["html", "json", "md"], default="json", help="Report format")
    p.add_argument("--export-alerts", metavar="FILE", help="Export alerts as JSON file")

    # Auth helpers
    p.add_argument("--set-cookies", nargs=2, metavar=("DOMAIN", "FILE"), help="Load cookies for domain")
    p.add_argument("--set-header", nargs=2, metavar=("NAME", "VALUE"), help="Set custom header")

    # Proxy
    p.add_argument("--proxy-url", metavar="URL", help="Send a URL through ZAP proxy")
    p.add_argument("--intercept-on", action="store_true", help="Enable break/intercept mode")
    p.add_argument("--intercept-off", action="store_true", help="Disable break/intercept mode")
    p.add_argument("--history", action="store_true", help="Show proxy history")
    p.add_argument("--filter", metavar="REGEX", help="Filter proxy history by regex")

    # Pipeline
    p.add_argument(
        "--hunt", nargs=2, metavar=("SCOPE_JSON", "OUTPUT_DIR"),
        help="Full automated hunt: scope.json + output directory",
    )

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    cfg = load_config()

    host = args.host or cfg.get("host", DEFAULT_HOST)
    port = args.port or cfg.get("port", DEFAULT_PORT)
    cfg["host"] = host
    cfg["port"] = port

    # Ensure at least one action was requested
    actions = [
        args.start, args.stop, args.status,
        args.spider, args.ajax_spider, args.active_scan,
        args.full_scan, args.authenticated_scan,
        args.alerts is not None, args.report, args.export_alerts,
        args.set_cookies, args.set_header,
        args.proxy_url, args.intercept_on, args.intercept_off,
        args.history, args.hunt,
    ]
    if not any(actions):
        parser.print_help()
        sys.exit(0)

    # --- Lifecycle ---
    if args.start:
        start_zap(host, port, cfg)
        return

    if args.stop:
        stop_zap(cfg)
        return

    if args.status:
        status_zap(cfg)
        return

    # --- Auth helpers (do these before scans) ---
    if args.set_cookies:
        zap = connect_zap(cfg)
        domain, cfile = args.set_cookies
        cookie_list = load_cookies_file(cfile)
        set_cookies(zap, domain, cookie_list)
        return

    if args.set_header:
        zap = connect_zap(cfg)
        set_header(zap, args.set_header[0], args.set_header[1])
        return

    # --- Scanning ---
    if args.spider:
        zap = connect_zap(cfg)
        spider_url(zap, args.spider)
        return

    if args.ajax_spider:
        zap = connect_zap(cfg)
        ajax_spider_url(zap, args.ajax_spider)
        return

    if args.active_scan:
        zap = connect_zap(cfg)
        active_scan_url(zap, args.active_scan)
        return

    if args.full_scan:
        zap = connect_zap(cfg)
        full_scan_url(zap, args.full_scan)
        return

    if args.authenticated_scan:
        if not args.cookies:
            error("--authenticated-scan requires --cookies <file>")
        zap = connect_zap(cfg)
        cookie_list = load_cookies_file(args.cookies)
        domain = urlparse(args.authenticated_scan).hostname or ""
        set_cookies(zap, domain, cookie_list)
        full_scan_url(zap, args.authenticated_scan)
        return

    # --- Results ---
    if args.alerts is not None:
        zap = connect_zap(cfg)
        base = None if args.alerts == "__all__" else args.alerts
        risk_filter = [r.strip() for r in args.risk.split(",")] if args.risk else None
        alerts = get_alerts(zap, base, risk_filter)
        print_alerts(alerts)
        return

    if args.export_alerts:
        zap = connect_zap(cfg)
        risk_filter = [r.strip() for r in args.risk.split(",")] if args.risk else None
        alerts = get_alerts(zap, risk_filter=risk_filter)
        export_alerts_json(alerts, args.export_alerts)
        return

    if args.report:
        zap = connect_zap(cfg)
        generate_report(zap, args.report, args.format)
        return

    # --- Proxy ---
    if args.proxy_url:
        zap = connect_zap(cfg)
        proxy_single_url(zap, args.proxy_url)
        return

    if args.intercept_on:
        zap = connect_zap(cfg)
        try:
            zap.core.set_mode("protect")
            zap._request(
                zap.base + "break/action/break/",
                {"type": "http-all", "state": "true", "apikey": cfg.get("api_key", "")},
            )
            log("Intercept/break mode ENABLED")
        except Exception as exc:
            log(f"Could not enable intercept: {exc}")
        return

    if args.intercept_off:
        zap = connect_zap(cfg)
        try:
            zap._request(
                zap.base + "break/action/break/",
                {"type": "http-all", "state": "false", "apikey": cfg.get("api_key", "")},
            )
            zap.core.set_mode("standard")
            log("Intercept/break mode DISABLED")
        except Exception as exc:
            log(f"Could not disable intercept: {exc}")
        return

    if args.history:
        zap = connect_zap(cfg)
        show_history(zap, args.filter)
        return

    # --- Pipeline ---
    if args.hunt:
        scope_json, out_dir = args.hunt
        hunt(scope_json, out_dir, cfg)
        return


if __name__ == "__main__":
    main()
