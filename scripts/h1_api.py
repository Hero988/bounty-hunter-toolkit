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

    # ensure_ascii=False preserves markdown characters properly
    # json.dumps handles all necessary escaping (\n, \", \\, etc.)
    body = json.dumps(data, ensure_ascii=False).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    # Handle SSL on Windows (some versions need explicit context)
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=60, context=ctx) as response:
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
    """Fetch ALL structured scopes for a program (handles pagination)."""
    all_scopes = []
    page = 1
    while True:
        success, data = api_request("GET", f"/hackers/programs/{program_handle}/structured_scopes?page[number]={page}&page[size]=100")
        if not success:
            if all_scopes:
                break  # Return what we have
            return None, data

        items = data.get("data", [])
        if not items:
            break

        for item in items:
            attrs = item.get("attributes", {})
            all_scopes.append({
                "id": item.get("id"),
                "asset_identifier": attrs.get("asset_identifier", ""),
                "asset_type": attrs.get("asset_type", ""),
                "eligible_for_bounty": attrs.get("eligible_for_bounty", False),
                "eligible_for_submission": attrs.get("eligible_for_submission", True),
                "max_severity": attrs.get("max_severity", ""),
                "instruction": attrs.get("instruction", "")
            })

        # Check for next page
        next_link = data.get("links", {}).get("next")
        if not next_link or len(items) < 100:
            break
        page += 1

    return all_scopes, None


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
    """Fetch ALL available weaknesses/CWEs for a program (handles pagination)."""
    all_weaknesses = []
    page = 1
    while True:
        success, data = api_request("GET", f"/hackers/programs/{program_handle}/weaknesses?page[number]={page}&page[size]=100")
        if not success:
            if all_weaknesses:
                break
            return None, data

        items = data.get("data", [])
        if not items:
            break

        for item in items:
            attrs = item.get("attributes", {})
            all_weaknesses.append({
                "id": int(item.get("id", 0)),
                "name": attrs.get("name", ""),
                "description": attrs.get("description", ""),
                "external_id": attrs.get("external_id", "")
            })

        next_link = data.get("links", {}).get("next")
        if not next_link or len(items) < 100:
            break
        page += 1

    return all_weaknesses, None


def find_weakness_id(program_handle, cwe_or_name):
    """Find weakness_id by CWE number or name."""
    weaknesses, error = get_weaknesses(program_handle)
    if error:
        return None, error

    cwe_lower = cwe_or_name.lower().replace("cwe-", "").strip()

    for w in weaknesses:
        # Match by CWE number
        ext_id = (w.get("external_id") or "").lower().replace("cwe-", "")
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
                  weakness_id=None, asset_identifier=None, cwe=None, dry_run=False):
    """
    Submit a report to HackerOne.

    NOTE: structured_scope_id is NOT sent — it causes HTTP 500 errors on HackerOne's API.
    The asset is identified by title/description instead. Triagers can set the scope manually.
    """
    # Auto-resolve weakness_id from CWE
    if not weakness_id and cwe:
        wid, err = find_weakness_id(program_handle, str(cwe))
        if wid:
            weakness_id = wid
            print(f"Resolved CWE-{cwe} -> weakness_id={wid}")
        else:
            print(f"Warning: Could not resolve CWE-{cwe}: {err}")
            print(f"  Weakness will not be set — you can set it manually on HackerOne after submission")

    # Build payload
    # NOTE: structured_scope_id is intentionally omitted — it causes HTTP 500 on some programs.
    # The triager can set the scope on the web UI based on the asset mentioned in the report.
    attributes = {
        "team_handle": program_handle,
        "title": title,
        "vulnerability_information": description,
        "impact": impact if impact else "See vulnerability description above for full impact details.",
        "severity_rating": severity
    }
    # weakness_id MUST be included when resolved — it maps to the Weakness field on HackerOne
    if weakness_id:
        attributes["weakness_id"] = int(weakness_id)

    payload = {
        "data": {
            "type": "report",
            "attributes": attributes
        }
    }

    print(f"\n{'[DRY RUN] ' if dry_run else ''}Report submission summary:")
    print(f"  Program: {program_handle}")
    print(f"  Title: {title[:100]}")
    print(f"  Severity: {severity}")
    print(f"  Weakness ID: {weakness_id or 'not set'}")
    print(f"  Description: {len(description)} chars")
    print(f"  Impact: {len(impact)} chars")
    if asset_identifier:
        print(f"  Asset (in title/description): {asset_identifier}")

    if dry_run:
        # Save payload for inspection
        print(f"\n[DRY RUN] Payload saved — review before submitting with --confirm")
        return "DRY_RUN", payload

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


def submit_from_file(report_file, program_handle, dry_run=False):
    """
    Parse a report .md file and submit it via API.

    The .md file follows this structure (matching HackerOne form fields):
    ## Asset — maps to asset context in description
    ## Weakness — CWE number, auto-resolved to weakness_id
    ## Severity — rating extracted (critical/high/medium/low)
    ## Title — report title
    ## Description — vulnerability_information field
    ## Steps to Reproduce — appended to vulnerability_information
    ## Complete Schema Discovered (or similar) — appended to vulnerability_information
    ## Impact — impact field
    ## Remediation — appended to vulnerability_information
    """
    import re

    with open(report_file, encoding="utf-8", errors="replace") as f:
        content = f.read()

    # Parse the markdown report into sections
    sections = {}
    current_section = None
    current_content = []

    for line in content.split("\n"):
        if line.startswith("## "):
            if current_section:
                sections[current_section] = "\n".join(current_content).strip()
            current_section = line[3:].strip()
            current_content = []
        elif line.startswith("# ") and not current_section:
            # Skip the H1 header (e.g., "# HackerOne Report - Finding A")
            continue
        else:
            current_content.append(line)
    if current_section:
        sections[current_section] = "\n".join(current_content).strip()

    # Build a case-insensitive lookup
    sections_lower = {k.lower(): v for k, v in sections.items()}

    # Extract metadata fields
    title = sections_lower.get("title", "")
    weakness_line = sections_lower.get("weakness", "")
    severity_line = sections_lower.get("severity", "")
    asset_line = sections_lower.get("asset", "")
    impact = sections_lower.get("impact", "")

    # Parse severity
    severity = "medium"
    for sev in ["critical", "high", "medium", "low", "none"]:
        if sev in severity_line.lower():
            severity = sev
            break

    # Parse CWE
    cwe = None
    cwe_match = re.search(r"CWE-(\d+)", weakness_line)
    if cwe_match:
        cwe = cwe_match.group(1)

    # Parse asset
    asset = ""
    asset_match = re.search(r"`([^`]+)`", asset_line)
    if asset_match:
        asset = asset_match.group(1)

    # Build vulnerability_information: put EVERYTHING in this one field.
    # The web UI puts description + steps + impact + everything into vulnerability_information.
    # The good manual reports (#3635894, #3636250) have 0 chars in the separate impact field —
    # everything is in vulnerability_information as one combined markdown document.

    # Reconstruct the full markdown report from the .md file, skipping only metadata headers
    metadata_sections = {"asset", "weakness", "severity", "title"}
    description_parts = []

    for section_name, section_content in sections.items():
        if section_name.lower() in metadata_sections:
            continue  # Skip metadata — these map to API fields, not description
        if not section_content.strip():
            continue
        description_parts.append(f"## {section_name}\n\n{section_content}")

    full_description = "\n\n".join(description_parts)

    # If title is empty, try the H1 header
    if not title:
        for line in content.split("\n"):
            if line.startswith("# ") and "finding" not in line.lower() and "report" not in line.lower():
                title = line[2:].strip()
                break

    # The impact field is REQUIRED by the API. If the impact is already in vulnerability_information
    # (which it should be since we include all sections), use impact as a short summary.
    # If impact section exists separately, use it; otherwise provide a default.
    impact_for_api = impact if impact else "See the Impact section in the vulnerability description above."

    print(f"Parsed report: {os.path.basename(report_file)}")
    print(f"  Title: {title[:100]}")
    print(f"  Severity: {severity}")
    print(f"  CWE: {cwe}")
    print(f"  Asset: {asset}")
    print(f"  vulnerability_information: {len(full_description)} chars ({full_description.count(chr(10))} lines)")
    print(f"  impact: {len(impact_for_api)} chars")
    print(f"  Has code blocks: {'```' in full_description}")
    print(f"  Has tables: {'|' in full_description and '---' in full_description}")

    if dry_run:
        payload_file = report_file.replace(".md", "-payload.json")
        result_id, payload = submit_report(
            program_handle=program_handle, title=title,
            description=full_description, impact=impact_for_api, severity=severity,
            cwe=cwe, asset_identifier=asset, dry_run=True
        )
        with open(payload_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"  Payload saved to: {payload_file}")
        print(f"\n  To submit for real: h1_api.py --submit {report_file} {program_handle} --confirm")
        return "DRY_RUN", None

    return submit_report(
        program_handle=program_handle, title=title,
        description=full_description, impact=impact_for_api, severity=severity,
        cwe=cwe, asset_identifier=asset
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
        print("  h1_api.py --scopes <program>                     # List program scopes with IDs")
        print("  h1_api.py --weaknesses <program>                 # List ALL program weaknesses")
        print("  h1_api.py --find-scope <program> <asset>         # Find scope ID for asset")
        print("  h1_api.py --find-weakness <program> <cwe>        # Find weakness ID for CWE")
        print("  h1_api.py --submit <report.md> <program>         # DRY RUN: preview submission (safe)")
        print("  h1_api.py --submit <report.md> <program> --confirm  # ACTUALLY submit (irreversible!)")
        print("  h1_api.py --status <report_id>                   # Check report status")
        print("  h1_api.py --my-reports                            # List your reports")
        print("  h1_api.py --hacktivity <program> [query]         # Search hacktivity for dedup")
        print("")
        print("IMPORTANT: --submit without --confirm is a dry run. It parses the report,")
        print("resolves CWE/scope IDs, and saves the payload for review. Only --confirm sends it.")
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
            print("Usage: h1_api.py --submit <report.md> <program> [--confirm]")
            print("  Without --confirm: dry run (safe, saves payload for review)")
            print("  With --confirm: ACTUALLY submits (irreversible!)")
            sys.exit(1)
        report_file = sys.argv[2]
        program = sys.argv[3]
        confirm = "--confirm" in sys.argv
        if not confirm:
            print("=" * 60)
            print("  DRY RUN MODE (safe — nothing will be submitted)")
            print("  Add --confirm to actually submit")
            print("=" * 60)
        report_id, err = submit_from_file(report_file, program, dry_run=not confirm)
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
