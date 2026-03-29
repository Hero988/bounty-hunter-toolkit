#!/usr/bin/env python3
"""
apk_analyzer.py - Android APK Security Analyzer for Bug Bounty Hunting

Automates APK download, decompilation, secret scanning, endpoint extraction,
and manifest analysis. Outputs structured JSON and a human-readable markdown report.

Usage:
    apk_analyzer.py <apk-file-or-package-name> <output-dir>
    apk_analyzer.py --download <package-name> <output-dir>
    apk_analyzer.py --scan <decompiled-dir> <output-dir>

Dependencies: Python 3.7+ stdlib only. Optional: jadx, curl.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Regex patterns for secret scanning
# ---------------------------------------------------------------------------

SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z_\-]{35}",
    "Firebase Key": r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "Generic API Key/Token": r"(?i)(?:Authorization|Bearer|api_key|apiKey|API_KEY|secret|password|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
    "Sentry DSN": r"(?i)(?:@sentry|sentry\.io|dsn.*sentry)",
    "Debug/Backdoor": r"(?i)(?:backdoor|godmode|god_mode|debug_menu|developer_menu|isDebug|debugMode|testMode)",
    "Internal URL": r"(?i)(?:\.int\b|\.internal|\.local|\.test\b|\-int\.|\-dev\.|\-qa\.|\-staging\.)",
    "Hardcoded Password": r"(?i)(?:password|passwd|pwd)\s*=\s*[\"'][^\"']+[\"']",
}

ENDPOINT_PATTERNS = {
    "Retrofit Annotation": r"@(?:GET|POST|PUT|DELETE|PATCH)\s*\(\s*\"([^\"]+)\"\s*\)",
    "Base URL": r"(?i)(?:baseUrl|BASE_URL|api_url|endpoint)\s*[:=]\s*[\"'](https?://[^\"']+)[\"']",
    "URL String": r"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\"'<>}{)(\]\\]*)?",
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd, timeout=300):
    """Run a shell command and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=isinstance(cmd, str),
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "Command not found"
    except subprocess.TimeoutExpired:
        return -2, "", "Command timed out"


def which(name):
    """Check if a command is available on PATH."""
    return shutil.which(name) is not None


def ensure_dir(path):
    """Create directory if it doesn't exist."""
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# APK Download
# ---------------------------------------------------------------------------

def try_curl_download(url, dest):
    """Attempt to download a URL using curl. Returns True on success."""
    if not which("curl"):
        return False
    rc, _, _ = run_cmd(["curl", "-fsSL", "-o", dest, "-L", url], timeout=120)
    return rc == 0 and os.path.isfile(dest) and os.path.getsize(dest) > 1000


def download_apk(package_name, output_dir):
    """Try multiple sources to download an APK. Returns path or None."""
    ensure_dir(output_dir)
    dest = os.path.join(output_dir, f"{package_name}.apk")

    # Source 1: APKPure
    print(f"[*] Trying APKPure for {package_name} ...")
    apkpure_url = f"https://d.apkpure.com/b/APK/{package_name}?version=latest"
    if try_curl_download(apkpure_url, dest):
        print(f"[+] Downloaded from APKPure -> {dest}")
        return dest

    # Source 2: APKCombo
    print(f"[*] Trying APKCombo for {package_name} ...")
    apkcombo_url = f"https://apkcombo.com/apk-downloader/?package={package_name}"
    if try_curl_download(apkcombo_url, dest):
        print(f"[+] Downloaded from APKCombo -> {dest}")
        return dest

    # Source 3: APKMirror search suggestion
    print(f"[*] APKMirror search: https://www.apkmirror.com/?s={package_name}")

    # All automated sources failed
    print("[!] Automated download failed. Manual options:")
    print(f"    1. APKPure:   https://apkpure.com/search?q={package_name}")
    print(f"    2. APKCombo:  https://apkcombo.com/search/{package_name}/")
    print(f"    3. APKMirror: https://www.apkmirror.com/?s={package_name}")
    print(f"    4. adb pull from a device: adb shell pm path {package_name}")
    print(f"    Place the APK at: {dest}")
    return None


# ---------------------------------------------------------------------------
# Decompilation
# ---------------------------------------------------------------------------

def decompile_apk(apk_path, output_dir):
    """Decompile APK using jadx (preferred) or fallback to unzip."""
    decompiled = os.path.join(output_dir, "decompiled")
    ensure_dir(decompiled)

    if which("jadx"):
        print("[*] Decompiling with jadx ...")
        rc, stdout, stderr = run_cmd(
            ["jadx", "-d", decompiled, "--no-res", "--no-debug-info", apk_path],
            timeout=600,
        )
        if rc == 0:
            print(f"[+] jadx decompilation complete -> {decompiled}")
            return decompiled
        else:
            print(f"[!] jadx returned {rc}, falling back to unzip.")
            print(f"    stderr: {stderr[:300]}")
    else:
        print("[!] jadx not found on PATH. Using unzip fallback (limited analysis).")

    # Fallback: basic zip extraction
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            zf.extractall(decompiled)
        print(f"[+] Extracted APK contents -> {decompiled}")
    except zipfile.BadZipFile:
        print("[!] File is not a valid ZIP/APK.")
        return None

    return decompiled


# ---------------------------------------------------------------------------
# Secret Scanning
# ---------------------------------------------------------------------------

def scan_file_for_secrets(filepath, patterns):
    """Scan a single file for secret patterns. Returns list of findings."""
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_no, line in enumerate(f, 1):
                for name, pattern in patterns.items():
                    for match in re.finditer(pattern, line):
                        findings.append({
                            "type": name,
                            "file": filepath,
                            "line": line_no,
                            "match": match.group(0)[:200],
                        })
    except (OSError, PermissionError):
        pass
    return findings


def scan_directory(scan_dir, patterns):
    """Recursively scan a directory for secrets."""
    findings = []
    skip_ext = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4",
                ".ogg", ".ttf", ".otf", ".woff", ".woff2", ".so", ".dex",
                ".class", ".jar", ".zip", ".apk", ".arsc"}
    scanned = 0
    for root, _dirs, files in os.walk(scan_dir):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in skip_ext:
                continue
            filepath = os.path.join(root, fname)
            findings.extend(scan_file_for_secrets(filepath, patterns))
            scanned += 1
    print(f"[*] Scanned {scanned} files, found {len(findings)} potential secrets.")
    return findings


# ---------------------------------------------------------------------------
# Endpoint Extraction
# ---------------------------------------------------------------------------

def extract_endpoints(scan_dir):
    """Extract API endpoints and URLs from decompiled source."""
    endpoints = {"retrofit": [], "base_urls": [], "urls": set()}
    text_ext = {".java", ".kt", ".xml", ".json", ".js", ".html", ".smali", ".txt", ".properties"}

    for root, _dirs, files in os.walk(scan_dir):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in text_ext:
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, PermissionError):
                continue

            # Retrofit annotations
            for m in re.finditer(ENDPOINT_PATTERNS["Retrofit Annotation"], content):
                endpoints["retrofit"].append({
                    "path": m.group(1),
                    "file": filepath,
                })

            # Base URLs
            for m in re.finditer(ENDPOINT_PATTERNS["Base URL"], content):
                endpoints["base_urls"].append({
                    "url": m.group(1),
                    "file": filepath,
                })

            # Generic URLs (deduplicated)
            for m in re.finditer(ENDPOINT_PATTERNS["URL String"], content):
                url = m.group(0).rstrip(".,;:!?")
                # Filter out common noise
                if any(skip in url for skip in [
                    "schemas.android.com", "www.w3.org", "xmlns",
                    "play.google.com", "developer.android.com",
                    "fonts.googleapis.com", "example.com",
                ]):
                    continue
                endpoints["urls"].add(url)

    endpoints["urls"] = sorted(endpoints["urls"])
    total = len(endpoints["retrofit"]) + len(endpoints["base_urls"]) + len(endpoints["urls"])
    print(f"[*] Found {total} endpoints/URLs ({len(endpoints['retrofit'])} Retrofit, "
          f"{len(endpoints['base_urls'])} base URLs, {len(endpoints['urls'])} generic URLs).")
    return endpoints


# ---------------------------------------------------------------------------
# AndroidManifest.xml Analysis
# ---------------------------------------------------------------------------

def analyze_manifest(scan_dir):
    """Parse AndroidManifest.xml for security-relevant info."""
    results = {
        "permissions": [],
        "exported_components": [],
        "js_interfaces": [],
        "network_config": {},
        "cleartext_traffic": None,
        "certificate_pinning": False,
        "deeplinks": [],
    }

    # Locate manifest
    manifest_path = None
    for root, _dirs, files in os.walk(scan_dir):
        for f in files:
            if f == "AndroidManifest.xml":
                candidate = os.path.join(root, f)
                manifest_path = candidate
                break
        if manifest_path:
            break

    if not manifest_path:
        print("[!] AndroidManifest.xml not found.")
        return results

    print(f"[*] Analyzing {manifest_path}")

    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError:
        return results

    # Try XML parsing first
    ns = {"android": "http://schemas.android.com/apk/res/android"}
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Permissions
        for perm in root.findall(".//uses-permission"):
            name = perm.get(f"{{{ns['android']}}}name", perm.get("android:name", ""))
            if name:
                results["permissions"].append(name)

        # Exported components
        for tag in ["activity", "service", "receiver", "provider"]:
            for comp in root.findall(f".//{tag}"):
                exported = comp.get(f"{{{ns['android']}}}exported",
                                    comp.get("android:exported", ""))
                name = comp.get(f"{{{ns['android']}}}name",
                                comp.get("android:name", "unknown"))
                if exported.lower() == "true":
                    results["exported_components"].append({
                        "type": tag,
                        "name": name,
                        "exported": True,
                    })
                # Deep links
                for intent in comp.findall(".//intent-filter"):
                    for data in intent.findall("data"):
                        scheme = data.get(f"{{{ns['android']}}}scheme",
                                          data.get("android:scheme", ""))
                        host = data.get(f"{{{ns['android']}}}host",
                                        data.get("android:host", ""))
                        path = data.get(f"{{{ns['android']}}}path",
                                        data.get("android:path", ""))
                        if scheme:
                            results["deeplinks"].append(
                                f"{scheme}://{host}{path}" if host else f"{scheme}://"
                            )

        # Cleartext traffic
        app = root.find("application")
        if app is not None:
            ct = app.get(f"{{{ns['android']}}}usesCleartextTraffic",
                         app.get("android:usesCleartextTraffic", ""))
            if ct:
                results["cleartext_traffic"] = ct.lower() == "true"

    except ET.ParseError:
        # Fallback to regex for broken XML (common in decompiled APKs)
        results["permissions"] = re.findall(
            r'uses-permission[^>]*android:name="([^"]+)"', content)
        exported_matches = re.findall(
            r'<(activity|service|receiver|provider)[^>]*android:name="([^"]+)"[^>]*android:exported="true"',
            content)
        for comp_type, comp_name in exported_matches:
            results["exported_components"].append({
                "type": comp_type, "name": comp_name, "exported": True
            })
        ct_match = re.search(r'usesCleartextTraffic="(true|false)"', content)
        if ct_match:
            results["cleartext_traffic"] = ct_match.group(1) == "true"

    # JavaScript Interfaces (scan all source files)
    for root_dir, _dirs, files in os.walk(scan_dir):
        for fname in files:
            if fname.endswith((".java", ".kt", ".smali")):
                fpath = os.path.join(root_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        fc = f.read()
                    if "@JavascriptInterface" in fc:
                        results["js_interfaces"].append(fpath)
                except OSError:
                    pass

    # Certificate pinning detection
    for root_dir, _dirs, files in os.walk(scan_dir):
        for fname in files:
            fpath = os.path.join(root_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    fc = f.read()
                if "CertificatePinner" in fc or "certificatePinner" in fc:
                    results["certificate_pinning"] = True
                    break
            except OSError:
                pass
        if results["certificate_pinning"]:
            break

    # Network security config
    nsc_match = re.search(r'networkSecurityConfig="@xml/([^"]+)"', content)
    if nsc_match:
        nsc_name = nsc_match.group(1)
        for root_dir, _dirs, files in os.walk(scan_dir):
            for fname in files:
                if fname == f"{nsc_name}.xml":
                    nsc_path = os.path.join(root_dir, fname)
                    try:
                        with open(nsc_path, "r", encoding="utf-8", errors="ignore") as f:
                            nsc_content = f.read()
                        results["network_config"]["file"] = nsc_path
                        if "cleartextTrafficPermitted" in nsc_content:
                            results["network_config"]["cleartext_in_nsc"] = True
                        results["network_config"]["raw_snippet"] = nsc_content[:1000]
                    except OSError:
                        pass

    exp_count = len(results["exported_components"])
    perm_count = len(results["permissions"])
    print(f"[*] Manifest: {perm_count} permissions, {exp_count} exported components, "
          f"{len(results['js_interfaces'])} JS interfaces, "
          f"{len(results['deeplinks'])} deeplinks.")
    return results


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_reports(output_dir, apk_name, secrets, endpoints, manifest):
    """Write JSON and markdown reports."""
    ensure_dir(output_dir)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    report_data = {
        "meta": {
            "tool": "apk_analyzer.py",
            "target": apk_name,
            "timestamp": timestamp,
        },
        "secrets": secrets,
        "endpoints": endpoints,
        "manifest": manifest,
    }

    # JSON report
    json_path = os.path.join(output_dir, "apk_analysis.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, default=str)
    print(f"[+] JSON report -> {json_path}")

    # Markdown report
    md_path = os.path.join(output_dir, "apk_analysis.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# APK Security Analysis: {apk_name}\n\n")
        f.write(f"**Generated:** {timestamp}\n\n")
        f.write("---\n\n")

        # Secrets
        f.write("## Secrets & Sensitive Data\n\n")
        if secrets:
            by_type = {}
            for s in secrets:
                by_type.setdefault(s["type"], []).append(s)
            for stype, items in sorted(by_type.items()):
                f.write(f"### {stype} ({len(items)} found)\n\n")
                for item in items[:20]:
                    rel = os.path.relpath(item["file"], output_dir) if output_dir else item["file"]
                    f.write(f"- `{rel}` L{item['line']}: `{item['match'][:100]}`\n")
                if len(items) > 20:
                    f.write(f"- ... and {len(items) - 20} more\n")
                f.write("\n")
        else:
            f.write("No secrets detected.\n\n")

        # Endpoints
        f.write("## API Endpoints\n\n")
        if endpoints.get("retrofit"):
            f.write("### Retrofit Endpoints\n\n")
            for ep in endpoints["retrofit"][:50]:
                f.write(f"- `{ep['path']}`\n")
            f.write("\n")

        if endpoints.get("base_urls"):
            f.write("### Base URLs\n\n")
            for ep in endpoints["base_urls"][:30]:
                f.write(f"- `{ep['url']}`\n")
            f.write("\n")

        if endpoints.get("urls"):
            f.write(f"### Discovered URLs ({len(endpoints['urls'])} total)\n\n")
            for url in endpoints["urls"][:100]:
                f.write(f"- `{url}`\n")
            if len(endpoints["urls"]) > 100:
                f.write(f"- ... and {len(endpoints['urls']) - 100} more (see JSON)\n")
            f.write("\n")

        # Manifest
        f.write("## AndroidManifest Analysis\n\n")

        if manifest.get("cleartext_traffic") is not None:
            status = "ALLOWED" if manifest["cleartext_traffic"] else "Blocked"
            f.write(f"**Cleartext Traffic:** {status}\n\n")

        f.write(f"**Certificate Pinning:** {'Detected' if manifest.get('certificate_pinning') else 'Not detected'}\n\n")

        if manifest.get("exported_components"):
            f.write(f"### Exported Components ({len(manifest['exported_components'])})\n\n")
            for comp in manifest["exported_components"]:
                f.write(f"- [{comp['type']}] `{comp['name']}`\n")
            f.write("\n")

        if manifest.get("js_interfaces"):
            f.write(f"### JavaScript Interfaces ({len(manifest['js_interfaces'])})\n\n")
            for jsi in manifest["js_interfaces"][:20]:
                rel = os.path.relpath(jsi, output_dir) if output_dir else jsi
                f.write(f"- `{rel}`\n")
            f.write("\n")

        if manifest.get("deeplinks"):
            f.write(f"### Deep Links ({len(manifest['deeplinks'])})\n\n")
            for dl in manifest["deeplinks"]:
                f.write(f"- `{dl}`\n")
            f.write("\n")

        if manifest.get("permissions"):
            f.write(f"### Permissions ({len(manifest['permissions'])})\n\n")
            dangerous = [
                "CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "WRITE_CONTACTS",
                "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_SMS",
                "SEND_SMS", "READ_PHONE_STATE", "READ_EXTERNAL_STORAGE",
                "WRITE_EXTERNAL_STORAGE", "READ_CALL_LOG",
            ]
            for perm in sorted(manifest["permissions"]):
                flag = " **[DANGEROUS]**" if any(d in perm for d in dangerous) else ""
                f.write(f"- `{perm}`{flag}\n")
            f.write("\n")

    print(f"[+] Markdown report -> {md_path}")
    return json_path, md_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Android APK Security Analyzer for Bug Bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s com.example.app ./output
  %(prog)s --download com.example.app ./output
  %(prog)s --scan ./decompiled_source ./output
  %(prog)s ./local_app.apk ./output
""",
    )
    parser.add_argument("target", help="APK file path, package name, or decompiled dir")
    parser.add_argument("output_dir", help="Directory for analysis output")
    parser.add_argument("--download", action="store_true",
                        help="Only download the APK (don't analyze)")
    parser.add_argument("--scan", action="store_true",
                        help="Scan an already-decompiled directory")

    args = parser.parse_args()
    output_dir = os.path.abspath(args.output_dir)
    ensure_dir(output_dir)

    print("=" * 60)
    print("  APK Security Analyzer - Bug Bounty Toolkit")
    print("=" * 60)
    print()

    # Determine mode
    if args.scan:
        # Scan pre-decompiled directory
        scan_dir = os.path.abspath(args.target)
        if not os.path.isdir(scan_dir):
            print(f"[!] Directory not found: {scan_dir}")
            sys.exit(1)
        apk_name = os.path.basename(scan_dir)
        print(f"[*] Scanning decompiled directory: {scan_dir}")

    else:
        target = args.target
        apk_path = None

        # Is it a local file?
        if os.path.isfile(target) and target.lower().endswith(".apk"):
            apk_path = os.path.abspath(target)
            apk_name = os.path.splitext(os.path.basename(apk_path))[0]
            print(f"[*] Using local APK: {apk_path}")
        else:
            # Treat as package name
            apk_name = target
            if args.download or not os.path.isfile(target):
                apk_path = download_apk(target, output_dir)
                if not apk_path:
                    if args.download:
                        sys.exit(1)
                    # Check if user placed it manually
                    candidate = os.path.join(output_dir, f"{target}.apk")
                    if os.path.isfile(candidate):
                        apk_path = candidate
                    else:
                        print(f"[!] No APK found. Place it at {candidate} and re-run.")
                        sys.exit(1)

        if args.download:
            print("[*] Download-only mode. Exiting.")
            sys.exit(0)

        # Decompile
        print()
        scan_dir = decompile_apk(apk_path, output_dir)
        if not scan_dir:
            print("[!] Decompilation failed.")
            sys.exit(1)

    # Run analysis
    print()
    print("[*] Scanning for secrets ...")
    secrets = scan_directory(scan_dir, SECRET_PATTERNS)

    print()
    print("[*] Extracting endpoints ...")
    endpoints = extract_endpoints(scan_dir)

    print()
    print("[*] Analyzing manifest ...")
    manifest = analyze_manifest(scan_dir)

    # Generate reports
    print()
    json_path, md_path = generate_reports(output_dir, apk_name, secrets, endpoints, manifest)

    # Summary
    print()
    print("=" * 60)
    print("  Analysis Complete")
    print("=" * 60)
    print(f"  Secrets found:       {len(secrets)}")
    total_ep = len(endpoints.get('retrofit', [])) + len(endpoints.get('base_urls', [])) + len(endpoints.get('urls', []))
    print(f"  Endpoints found:     {total_ep}")
    print(f"  Exported components: {len(manifest.get('exported_components', []))}")
    print(f"  JS interfaces:       {len(manifest.get('js_interfaces', []))}")
    print(f"  Deep links:          {len(manifest.get('deeplinks', []))}")
    print(f"  Cleartext traffic:   {manifest.get('cleartext_traffic', 'Unknown')}")
    print(f"  Cert pinning:        {manifest.get('certificate_pinning', False)}")
    print()
    print(f"  JSON: {json_path}")
    print(f"  Report: {md_path}")
    print()


if __name__ == "__main__":
    main()
