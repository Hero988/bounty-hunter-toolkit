#!/usr/bin/env python3
"""
Intigriti Researcher API Helper

Usage:
    python intigriti_api.py --setup <token>              Save API token
    python intigriti_api.py --test                       Test API connection
    python intigriti_api.py --list [--bounty-only]       List all programs
    python intigriti_api.py --search <handle>             Find program by handle
    python intigriti_api.py --scopes <program-id>         Get in-scope domains
    python intigriti_api.py --details <program-id>        Get full program details
    python intigriti_api.py --rules <program-id>          Get rules of engagement
    python intigriti_api.py --payouts                     List your payouts
    python intigriti_api.py --activities [--following]     Recent program changes

API Docs: https://api.intigriti.com/external/researcher/swagger/index.html
Token:    https://app.intigriti.com/researcher/personal-access-tokens
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error

BASE_URL = "https://api.intigriti.com/external/researcher"
TOOLKIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN_FILE = os.path.join(TOOLKIT_DIR, ".intigriti-token")

# Enum mappings
DOMAIN_TYPES = {1: "Url", 2: "Android", 3: "iOS", 4: "IpRange", 6: "Other", 7: "Wildcard"}
TIERS = {1: "No Bounty", 2: "Tier 3", 3: "Tier 2", 4: "Tier 1", 5: "Out Of Scope"}
PROGRAM_STATUS = {3: "Open", 4: "Suspended", 5: "Closing"}
PROGRAM_TYPE = {1: "Bug Bounty", 2: "Hybrid"}
CONFIDENTIALITY = {1: "Invite Only", 2: "Application", 3: "Registered", 4: "Public"}


def get_token():
    """Load token from file or environment variable."""
    token = os.environ.get("INTIGRITI_TOKEN")
    if token:
        return token.strip()
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE) as f:
            return f.read().strip()
    return None


def api_request(path, token=None):
    """Make an authenticated GET request to the Intigriti API."""
    if not token:
        token = get_token()
    if not token:
        print("[!] No API token configured.")
        print("    Set up: python intigriti_api.py --setup <your-token>")
        print("    Get token: https://app.intigriti.com/researcher/personal-access-tokens")
        sys.exit(1)

    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "bounty-hunter-toolkit/1.2.0")

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("[!] API token is invalid or expired.")
            print("    Refresh at: https://app.intigriti.com/researcher/personal-access-tokens")
        elif e.code == 403:
            print("[!] 403 Forbidden — you may need to accept updated T&Cs on the web UI.")
        elif e.code == 404:
            print(f"[!] 404 Not Found: {url}")
        else:
            print(f"[!] HTTP {e.code}: {e.reason}")
        return None
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        return None


def cmd_setup(args):
    """Save API token to file."""
    with open(TOKEN_FILE, "w") as f:
        f.write(args.token.strip())
    print(f"[+] Token saved to {TOKEN_FILE}")
    # Test the token
    data = api_request("/v1/programs?limit=1")
    if data:
        print(f"[+] API connection: OK ({data.get('maxCount', '?')} programs accessible)")
    else:
        print("[!] API connection: FAILED")


def cmd_test(args):
    """Test API connection."""
    token = get_token()
    if not token:
        print("API connection: FAILED - No token configured")
        print("Setup: python intigriti_api.py --setup <token>")
        return
    data = api_request("/v1/programs?limit=1")
    if data:
        print(f"API connection: OK")
        print(f"Programs accessible: {data.get('maxCount', '?')}")
    else:
        print("API connection: FAILED")


def cmd_list(args):
    """List all accessible programs."""
    params = "?limit=500&offset=0&statusId=3"  # Open programs only
    if hasattr(args, 'bounty_only') and args.bounty_only:
        params += "&typeId=1"  # Bug Bounty type only

    data = api_request(f"/v1/programs{params}")
    if not data:
        return

    programs = data.get("records", [])
    print(f"[+] {data.get('maxCount', len(programs))} programs found\n")
    print(f"{'Handle':<30} {'Name':<40} {'Type':<12} {'Bounty Range':<20} {'Access'}")
    print("-" * 130)

    for p in programs:
        handle = p.get("handle", "?")[:29]
        name = p.get("name", "?")[:39]
        ptype = p.get("type", {}).get("value", "?")
        min_b = p.get("minBounty", {})
        max_b = p.get("maxBounty", {})
        bounty = f"{min_b.get('currency', '?')}{min_b.get('value', 0):.0f}-{max_b.get('value', 0):.0f}"
        access = p.get("confidentialityLevel", {}).get("value", "?")
        print(f"{handle:<30} {name:<40} {ptype:<12} {bounty:<20} {access}")


def cmd_search(args):
    """Find a program by handle."""
    data = api_request("/v1/programs?limit=500&offset=0&statusId=3")
    if not data:
        return

    matches = [p for p in data.get("records", [])
               if args.handle.lower() in p.get("handle", "").lower()
               or args.handle.lower() in p.get("name", "").lower()]

    if not matches:
        print(f"[!] No program found matching '{args.handle}'")
        return

    for p in matches:
        print(f"Program: {p['name']}")
        print(f"  Handle: {p['handle']}")
        print(f"  ID: {p['id']}")
        print(f"  Type: {p.get('type', {}).get('value', '?')}")
        print(f"  Status: {p.get('status', {}).get('value', '?')}")
        print(f"  Bounty: {p.get('minBounty', {}).get('currency', '?')}"
              f"{p.get('minBounty', {}).get('value', 0):.0f} - "
              f"{p.get('maxBounty', {}).get('value', 0):.0f}")
        print(f"  Access: {p.get('confidentialityLevel', {}).get('value', '?')}")
        print(f"  URL: {p.get('webLinks', {}).get('detail', '?')}")
        print()


def cmd_scopes(args):
    """Get in-scope domains for a program."""
    data = api_request(f"/v1/programs/{args.program_id}")
    if not data:
        return

    domains = (data.get("domains") or {}).get("content") or []
    print(f"[+] Program: {data.get('name', '?')}")
    print(f"[+] {len(domains)} domains/assets found\n")

    in_scope = [d for d in domains if d.get("tier", {}).get("id") != 5]
    out_scope = [d for d in domains if d.get("tier", {}).get("id") == 5]

    if in_scope:
        print("IN SCOPE:")
        for d in sorted(in_scope, key=lambda x: x.get("tier", {}).get("id", 99), reverse=True):
            tier = d.get("tier", {}).get("value", "?")
            dtype = d.get("type", {}).get("value", "?")
            endpoint = d.get("endpoint", "?")
            desc = d.get("description", "")
            print(f"  [{tier}] ({dtype}) {endpoint}")
            if desc:
                print(f"           {desc[:80]}")

    if out_scope:
        print("\nOUT OF SCOPE:")
        for d in out_scope:
            print(f"  {d.get('endpoint', '?')}")

    # Also show testing requirements
    rules = (data.get("rulesOfEngagement") or {}).get("content")
    if rules:
        reqs = rules.get("testingRequirements", {})
        print("\nTESTING REQUIREMENTS:")
        if reqs.get("userAgent"):
            print(f"  Required User-Agent: {reqs['userAgent']}")
        if reqs.get("requestHeader"):
            print(f"  Required Header: {reqs['requestHeader']}")
        if reqs.get("automatedTooling") is not None:
            print(f"  Automated Tooling Policy: {reqs['automatedTooling']}")
        if reqs.get("intigritiMe"):
            print("  Intigriti VPN/Proxy: REQUIRED")


def cmd_details(args):
    """Get full program details as JSON."""
    data = api_request(f"/v1/programs/{args.program_id}")
    if data:
        print(json.dumps(data, indent=2))


def cmd_rules(args):
    """Get rules of engagement."""
    data = api_request(f"/v1/programs/{args.program_id}")
    if not data:
        return

    rules = (data.get("rulesOfEngagement") or {}).get("content")
    if not rules:
        print("[!] No rules of engagement found")
        return

    print(f"[+] Rules for: {data.get('name', '?')}")
    print(f"[+] Safe Harbour: {rules.get('safeHarbour', False)}")
    print(f"\n{rules.get('description', 'No description')}")

    reqs = rules.get("testingRequirements", {})
    if any(reqs.values()):
        print("\nTesting Requirements:")
        for k, v in reqs.items():
            if v is not None and v is not False:
                print(f"  {k}: {v}")


def cmd_payouts(args):
    """List payouts."""
    data = api_request("/v1/payouts?limit=500")
    if not data:
        return

    payouts = data.get("records", [])
    if not payouts:
        print("[*] No payouts found")
        return

    print(f"[+] {len(payouts)} payouts found\n")
    for p in payouts:
        amount = p.get("amount", {})
        status = p.get("status", {}).get("value", "?")
        print(f"  {amount.get('currency', '?')}{amount.get('value', 0):.2f} - {status}")


def cmd_activities(args):
    """List recent program activities."""
    params = "?limit=50"
    if hasattr(args, 'following') and args.following:
        params += "&following=true"

    data = api_request(f"/v1/programs/activities{params}")
    if not data:
        return

    activities = data.get("records", [])
    print(f"[+] {len(activities)} recent activities\n")
    for a in activities:
        atype = a.get("type", {}).get("value", "?")
        pid = a.get("programId", "?")[:8]
        print(f"  [{pid}...] {atype}")


def main():
    parser = argparse.ArgumentParser(description="Intigriti Researcher API Helper")
    sub = parser.add_subparsers(dest="command")

    # Allow flat argument style too
    parser.add_argument("--setup", metavar="TOKEN", dest="setup_token", help="Save API token")
    parser.add_argument("--test", action="store_true", help="Test API connection")
    parser.add_argument("--list", action="store_true", help="List programs")
    parser.add_argument("--bounty-only", action="store_true", help="Only show bounty programs")
    parser.add_argument("--search", metavar="HANDLE", help="Search for program by handle/name")
    parser.add_argument("--scopes", metavar="PROGRAM_ID", help="Get in-scope domains")
    parser.add_argument("--details", metavar="PROGRAM_ID", help="Get full program details (JSON)")
    parser.add_argument("--rules", metavar="PROGRAM_ID", help="Get rules of engagement")
    parser.add_argument("--payouts", action="store_true", help="List your payouts")
    parser.add_argument("--activities", action="store_true", help="Recent program changes")
    parser.add_argument("--following", action="store_true", help="Filter to followed programs")

    args = parser.parse_args()

    if args.setup_token:
        args.token = args.setup_token
        cmd_setup(args)
    elif args.test:
        cmd_test(args)
    elif args.list:
        cmd_list(args)
    elif args.search:
        args.handle = args.search
        cmd_search(args)
    elif args.scopes:
        args.program_id = args.scopes
        cmd_scopes(args)
    elif args.details:
        args.program_id = args.details
        cmd_details(args)
    elif args.rules:
        args.program_id = args.rules
        cmd_rules(args)
    elif args.payouts:
        cmd_payouts(args)
    elif args.activities:
        cmd_activities(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
