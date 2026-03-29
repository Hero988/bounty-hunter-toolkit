#!/usr/bin/env python3
"""
HackerOne API integration for bounty-hunter-toolkit.
Handles: API token setup, scope fetching, weakness lookup, report submission,
         report status checking, and hacktivity search.

Authentication: HTTP Basic Auth with API token identifier + value.
Create token at: https://hackerone.com/settings/api_token/edit
"""

import base64
import json
import os
import sys
import time
import urllib.request
import urllib.error
import urllib.parse

HOME = os.path.expanduser("~")
CONFIG_FILE = os.path.join(HOME, ".bounty-hunter-data", "h1-config.json")
API_BASE = "https://api.hackerone.com/v1"


# ============================================================
# Configuration
# ============================================================

def load_config():
    """Load HackerOne API config."""
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def save_config(config):
    """Save HackerOne API config."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def setup_token(identifier, token):
    """Save API token credentials."""
    config = load_config()
    config["api_identifier"] = identifier
    config["api_token"] = token
    config["configured_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_config(config)
    print(f"API token saved to {CONFIG_FILE}")
    print("Testing connection...")
    success, data = api_request("GET", "/hackers/me/reports?page[size]=1")
    if success:
        print("SUCCESS: API connection verified")
    else:
        print(f"WARNING: Connection test failed - {data}")


def get_auth_header():
    """Get the Authorization header value."""
    config = load_config()
    identifier = config.get("api_identifier", "")
    token = config.get("api_token", "")
    if not identifier or not token:
        return None
    credentials = base64.b64encode(f"{identifier}:{token}".encode()).decode()
    return f"Basic {credentials}"


# ============================================================
# API Request Helper
# ============================================================

def api_request(method, path, data=None, retries=3):
    """Make an authenticated API request. Returns (success, response_data)."""
    auth = get_auth_header()
    if not auth:
        return False, "No API token configured. Run: h1_api.py --setup <identifier> <token>"

    url = f"{API_BASE}{path}" if path.startswith("/") else f"{API_BASE}/{path}"

    headers = {
        "Authorization": auth,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                response_data = json.loads(response.read().decode("utf-8"))
                return True, response_data
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            if e.code == 429:
                # Rate limited — wait and retry
                retry_after = int(e.headers.get("Retry-After", 5))
                if attempt < retries - 1:
                    print(f"Rate limited. Waiting {retry_after}s...")
                    time.sleep(retry_after)
                    continue
            try:
                error_data = json.loads(error_body)
            except json.JSONDecodeError:
                error_data = {"raw": error_body[:500]}
            return False, {"status": e.code, "errors": error_data}
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            return False, {"error": str(e)}

    return False, "Max retries exceeded"


# ============================================================
# Scope & Weakness Lookup
# ============================================================

def get_structured_scopes(program_handle):
    """Fetch structured scopes for a program. Returns list of scope items."""
    success, data = api_request("GET", f"/hackers/programs/{program_handle}/structured_scopes")
    if not success:
        return None, data

    scopes = []
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        scopes.append({
            "id": item.get("id"),
            "asset_identifier": attrs.get("asset_identifier", ""),
            "asset_type": attrs.get("asset_type", ""),
            "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
            "eligible_for_submission": attrs.get("eligible_for_submission", True),
            "max_severity": attrs.get("max_severity", ""),
            "instruction": attrs.get("instruction", "")
        })
    return scopes, None


def find_scope_id(program_handle, asset_identifier):
    """Find the structured_scope_id for a specific asset."""
    scopes, error = get_structured_scopes(program_handle)
    if error:
        return None, error

    # Exact match first
    for scope in scopes:
        if scope["asset_identifier"] == asset_identifier:
            return int(scope["id"]), None

    # Wildcard match
    for scope in scopes:
        ident = scope["asset_identifier"]
        if ident.startswith("*."):
            base = ident[2:]
            if asset_identifier.endswith(base) or asset_identifier == base:
                return int(scope["id"]), None

    # Partial match
    for scope in scopes:
        if asset_identifier in scope["asset_identifier"] or scope["asset_identifier"] in asset_identifier:
            return int(scope["id"]), None

    return None, f"No scope found for {asset_identifier}"


def get_weaknesses(program_handle):
    """Fetch available weaknesses (CWEs) for a program."""
    success, data = api_request("GET", f"/hackers/programs/{program_handle}/weaknesses")
    if not success:
        return None, data

    weaknesses = []
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        weaknesses.append({
            "id": int(item.get("id", 0)),
            "name": attrs.get("name", ""),
            "description": attrs.get("description", ""),
            "external_id": attrs.get("external_id", "")
        })
    return weaknesses, None


def find_weakness_id(program_handle, cwe_or_name):
    """Find weakness_id by CWE number or name."""
    weaknesses, error = get_weaknesses(program_handle)
    if error:
        return None, error

    cwe_lower = cwe_or_name.lower().replace("cwe-", "").strip()

    for w in weaknesses:
        # Match by CWE number
        ext_id = w["external_id"].lower().replace("cwe-", "")
        if ext_id == cwe_lower:
            return w["id"], None
        # Match by name
        if cwe_lower in w["name"].lower():
            return w["id"], None

    return None, f"No weakness found for {cwe_or_name}"


# ============================================================
# Report Submission
# ============================================================

def submit_report(program_handle, title, description, impact, severity="medium",
                  weakness_id=None, scope_id=None, asset_identifier=None,
                  cwe=None):
    """
    Submit a report to HackerOne.

    Args:
        program_handle: Program handle (e.g., "x")
        title: Report title
        description: Full vulnerability description + steps to reproduce
        impact: Impact statement
        severity: none/low/medium/high/critical
        weakness_id: Direct weakness ID (optional, auto-resolved from cwe)
        scope_id: Direct scope ID (optional, auto-resolved from asset_identifier)
        asset_identifier: Asset name to auto-resolve scope ID
        cwe: CWE number to auto-resolve weakness ID
    """
    # Auto-resolve weakness_id from CWE
    if not weakness_id and cwe:
        wid, err = find_weakness_id(program_handle, str(cwe))
        if wid:
            weakness_id = wid
            print(f"Resolved CWE-{cwe} → weakness_id={wid}")
        else:
            print(f"Warning: Could not resolve CWE-{cwe}: {err}")

    # Auto-resolve scope_id from asset
    if not scope_id and asset_identifier:
        sid, err = find_scope_id(program_handle, asset_identifier)
        if sid:
            scope_id = sid
            print(f"Resolved {asset_identifier} → scope_id={sid}")
        else:
            print(f"Warning: Could not resolve scope for {asset_identifier}: {err}")

    # Build payload
    attributes = {
        "team_handle": program_handle,
        "title": title,
        "vulnerability_information": description,
        "impact": impact,
        "severity_rating": severity
    }
    if weakness_id:
        attributes["weakness_id"] = weakness_id
    if scope_id:
        attributes["structured_scope_id"] = scope_id

    payload = {
        "data": {
            "type": "report",
            "attributes": attributes
        }
    }

    print(f"\nSubmitting report to {program_handle}...")
    print(f"  Title: {title}")
    print(f"  Severity: {severity}")
    if weakness_id:
        print(f"  Weakness ID: {weakness_id}")
    if scope_id:
        print(f"  Scope ID: {scope_id}")

    success, data = api_request("POST", "/hackers/reports", payload)

    if success:
        report_id = data.get("data", {}).get("id", "unknown")
        state = data.get("data", {}).get("attributes", {}).get("state", "unknown")
        print(f"\nSUCCESS: Report submitted!")
        print(f"  Report ID: {report_id}")
        print(f"  State: {state}")
        print(f"  URL: https://hackerone.com/reports/{report_id}")
        return report_id, None
    else:
        print(f"\nFAILED: {json.dumps(data, indent=2)}")
        return None, data


def submit_from_file(report_file, program_handle):
    """Parse a report .md file and submit it via API."""
    with open(report_file) as f:
        content = f.read()

    # Parse the markdown report
    sections = {}
    current_section = None
    current_content = []

    for line in content.split("\n"):
        if line.startswith("## "):
            if current_section:
                sections[current_section] = "\n".join(current_content).strip()
            current_section = line[3:].strip().lower()
            current_content = []
        else:
            current_content.append(line)
    if current_section:
        sections[current_section] = "\n".join(current_content).strip()

    # Extract fields
    title = sections.get("title", "")
    description = sections.get("description", "")
    steps = sections.get("steps to reproduce", "")
    impact = sections.get("impact", "")
    weakness_line = sections.get("weakness", "")
    severity_line = sections.get("severity", "")
    asset_line = sections.get("asset", "")
    remediation = sections.get("remediation", sections.get("remediation (optional)", ""))

    # Parse severity
    severity = "medium"
    for sev in ["critical", "high", "medium", "low", "none"]:
        if sev in severity_line.lower():
            severity = sev
            break

    # Parse CWE
    cwe = None
    import re
    cwe_match = re.search(r"CWE-(\d+)", weakness_line)
    if cwe_match:
        cwe = cwe_match.group(1)

    # Parse asset
    asset = ""
    asset_match = re.search(r"`([^`]+)`", asset_line)
    if asset_match:
        asset = asset_match.group(1)

    # Combine description + steps + remediation
    full_description = description
    if steps:
        full_description += "\n\n## Steps to Reproduce\n" + steps
    if remediation:
        full_description += "\n\n## Remediation\n" + remediation

    if not title:
        # Try to get title from first H1
        for line in content.split("\n"):
            if line.startswith("# ") and "finding" not in line.lower():
                title = line[2:].strip()
                break

    print(f"Parsed report: {os.path.basename(report_file)}")
    print(f"  Title: {title[:80]}")
    print(f"  Severity: {severity}")
    print(f"  CWE: {cwe}")
    print(f"  Asset: {asset}")
    print(f"  Description: {len(full_description)} chars")
    print(f"  Impact: {len(impact)} chars")

    return submit_report(
        program_handle=program_handle,
        title=title,
        description=full_description,
        impact=impact,
        severity=severity,
        cwe=cwe,
        asset_identifier=asset
    )


# ============================================================
# Report Status
# ============================================================

def check_report(report_id):
    """Check the status of a submitted report."""
    success, data = api_request("GET", f"/hackers/reports/{report_id}")
    if not success:
        return None, data

    attrs = data.get("data", {}).get("attributes", {})
    return {
        "id": data["data"]["id"],
        "title": attrs.get("title", ""),
        "state": attrs.get("state", ""),
        "created_at": attrs.get("created_at", ""),
        "triaged_at": attrs.get("triaged_at"),
        "closed_at": attrs.get("closed_at"),
        "bounty_awarded_at": attrs.get("bounty_awarded_at"),
    }, None


def list_my_reports(page_size=10):
    """List your submitted reports."""
    success, data = api_request("GET", f"/hackers/me/reports?page[size]={page_size}")
    if not success:
        return None, data

    reports = []
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        reports.append({
            "id": item["id"],
            "title": attrs.get("title", ""),
            "state": attrs.get("state", ""),
            "created_at": attrs.get("created_at", "")[:10],
            "severity": attrs.get("severity_rating", "")
        })
    return reports, None


# ============================================================
# Hacktivity Search (Dedup)
# ============================================================

def search_hacktivity(program_handle, query="", severity=None):
    """Search hacktivity for a program (for dedup checking)."""
    q_parts = [f"team:{program_handle}"]
    if severity:
        q_parts.append(f"severity_rating:{severity}")
    if query:
        q_parts.append(query)
    query_string = " AND ".join(q_parts)
    encoded = urllib.parse.quote(query_string)

    success, data = api_request("GET", f"/hackers/hacktivity?queryString={encoded}&page[size]=10")
    if not success:
        return None, data

    results = []
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        results.append({
            "id": item["id"],
            "title": attrs.get("title", ""),
            "severity": attrs.get("severity_rating", ""),
            "state": attrs.get("state", ""),
            "disclosed_at": attrs.get("disclosed_at", "")
        })
    return results, None


# ============================================================
# CLI
# ============================================================

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  h1_api.py --setup <identifier> <token>           # Save API credentials")
        print("  h1_api.py --test                                  # Test API connection")
        print("  h1_api.py --scopes <program>                     # List program scopes")
        print("  h1_api.py --weaknesses <program>                 # List program weaknesses")
        print("  h1_api.py --find-scope <program> <asset>         # Find scope ID for asset")
        print("  h1_api.py --find-weakness <program> <cwe>        # Find weakness ID for CWE")
        print("  h1_api.py --submit <report.md> <program>         # Submit report from .md file")
        print("  h1_api.py --status <report_id>                   # Check report status")
        print("  h1_api.py --my-reports                            # List your reports")
        print("  h1_api.py --hacktivity <program> [query]         # Search hacktivity")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "--setup":
        if len(sys.argv) < 4:
            print("Usage: h1_api.py --setup <identifier> <token>")
            print("Create token at: https://hackerone.com/settings/api_token/edit")
            sys.exit(1)
        setup_token(sys.argv[2], sys.argv[3])

    elif cmd == "--test":
        auth = get_auth_header()
        if not auth:
            print("No API token configured. Run: h1_api.py --setup <identifier> <token>")
            sys.exit(1)
        success, data = api_request("GET", "/hackers/me/reports?page[size]=1")
        if success:
            print("API connection: OK")
        else:
            print(f"API connection: FAILED - {data}")

    elif cmd == "--scopes":
        program = sys.argv[2] if len(sys.argv) > 2 else ""
        scopes, err = get_structured_scopes(program)
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        for s in scopes:
            bounty = "BOUNTY" if s["eligible_for_bounty"] else "no-bounty"
            print(f"  [{s['id']}] {s['asset_identifier']} ({s['asset_type']}) — {bounty}, max={s['max_severity']}")

    elif cmd == "--weaknesses":
        program = sys.argv[2] if len(sys.argv) > 2 else ""
        weaknesses, err = get_weaknesses(program)
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        for w in weaknesses:
            print(f"  [{w['id']}] {w['external_id']}: {w['name']}")

    elif cmd == "--find-scope":
        program = sys.argv[2] if len(sys.argv) > 2 else ""
        asset = sys.argv[3] if len(sys.argv) > 3 else ""
        sid, err = find_scope_id(program, asset)
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        print(f"scope_id={sid}")

    elif cmd == "--find-weakness":
        program = sys.argv[2] if len(sys.argv) > 2 else ""
        cwe = sys.argv[3] if len(sys.argv) > 3 else ""
        wid, err = find_weakness_id(program, cwe)
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        print(f"weakness_id={wid}")

    elif cmd == "--submit":
        if len(sys.argv) < 4:
            print("Usage: h1_api.py --submit <report.md> <program>")
            sys.exit(1)
        report_file = sys.argv[2]
        program = sys.argv[3]
        report_id, err = submit_from_file(report_file, program)
        if err:
            sys.exit(1)

    elif cmd == "--status":
        report_id = sys.argv[2] if len(sys.argv) > 2 else ""
        result, err = check_report(report_id)
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        print(json.dumps(result, indent=2))

    elif cmd == "--my-reports":
        reports, err = list_my_reports()
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        for r in reports:
            print(f"  [{r['state']}] #{r['id']} — {r['title'][:60]} ({r['created_at']})")

    elif cmd == "--hacktivity":
        program = sys.argv[2] if len(sys.argv) > 2 else ""
        query = sys.argv[3] if len(sys.argv) > 3 else ""
        results, err = search_hacktivity(program, query)
        if err:
            print(f"Error: {err}")
            sys.exit(1)
        for r in results:
            print(f"  [{r['severity']}] {r['title'][:60]} ({r['disclosed_at'][:10] if r['disclosed_at'] else 'undisclosed'})")

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
