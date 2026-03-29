#!/usr/bin/env python3
"""
Parse bug bounty program scope from platform URLs or raw domains.
Outputs structured scope.json for use by scope_guard.py.

Supports: HackerOne, Bugcrowd, Intigriti, Immunefi, raw domains.
"""

import json
import os
import re
import sys
from urllib.parse import urlparse


def detect_platform(url_or_domain):
    """Detect which bug bounty platform a URL belongs to."""
    url = url_or_domain.lower().strip()
    if "hackerone.com" in url:
        return "hackerone", url
    elif "bugcrowd.com" in url:
        return "bugcrowd", url
    elif "intigriti.com" in url:
        return "intigriti", url
    elif "immunefi.com" in url:
        return "immunefi", url
    else:
        return "raw_domain", url


def extract_program_handle(url, platform):
    """Extract the program handle/slug from a platform URL."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    if not path_parts:
        return None
    if platform == "hackerone":
        return path_parts[0]
    elif platform == "bugcrowd":
        return path_parts[0]
    elif platform == "intigriti":
        # intigriti.com/programs/<company>/<program>
        if len(path_parts) >= 3 and path_parts[0] == "programs":
            return path_parts[2]
        return path_parts[-1]
    elif platform == "immunefi":
        # immunefi.com/bug-bounty/<program>
        if len(path_parts) >= 2:
            return path_parts[-1]
        return path_parts[0]
    return path_parts[0]


def create_scope_template(program_handle, platform, domains=None):
    """Create a scope.json template."""
    scope = {
        "program": program_handle or "unknown",
        "platform": platform,
        "program_url": "",
        "in_scope": [],
        "out_of_scope": [],
        "excluded_vuln_types": [],
        "bounty_table": {},
        "safe_harbor": True,
        "notes": ""
    }
    if domains:
        for domain in domains:
            scope["in_scope"].append({
                "identifier": domain,
                "type": "URL",
                "bounty": True,
                "max_severity": "critical"
            })
    return scope


def parse_raw_domain(domain):
    """Create scope from a raw domain input."""
    domain = domain.strip().lower()
    if "://" in domain:
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    # Remove any path
    domain = domain.split("/")[0]
    # Remove port
    if ":" in domain:
        domain = domain.split(":")[0]
    return create_scope_template(domain, "manual", [domain])


def generate_fetch_instructions(platform, url, program_handle):
    """Generate instructions for Claude to fetch and parse scope."""
    instructions = {
        "hackerone": f"""## Scope Fetch Instructions

Use WebFetch to retrieve the program page and extract scope information:

1. Fetch the program page: `{url}`
2. Look for the "Scope" or "Policy" section
3. Extract ALL in-scope assets (domains, wildcards, IPs, APIs)
4. Extract ALL out-of-scope assets
5. Extract the bounty table (severity -> reward range)
6. Extract excluded vulnerability types (e.g., "self-XSS", "rate limiting")
7. Note any special program rules

Then use the scope_parser.py --from-json command to create scope.json from the extracted data.

Example scope.json structure:
```json
{{
  "program": "{program_handle}",
  "platform": "hackerone",
  "program_url": "{url}",
  "in_scope": [
    {{"identifier": "*.example.com", "type": "URL", "bounty": true, "max_severity": "critical"}},
    {{"identifier": "api.example.com", "type": "API", "bounty": true, "max_severity": "critical"}}
  ],
  "out_of_scope": [
    {{"identifier": "blog.example.com", "type": "URL"}},
    {{"identifier": "*.staging.example.com", "type": "URL"}}
  ],
  "excluded_vuln_types": ["rate_limiting", "self_xss", "best_practices", "missing_headers"],
  "bounty_table": {{
    "critical": "$5000-$25000",
    "high": "$2500-$5000",
    "medium": "$500-$2500",
    "low": "$100-$500"
  }},
  "safe_harbor": true,
  "notes": ""
}}
```""",
        "bugcrowd": f"""## Scope Fetch Instructions

Use WebFetch to retrieve the Bugcrowd program page:

1. Fetch: `{url}`
2. Look for the "Scope" and "Target" sections
3. Extract in-scope targets with their priority (P1-P5)
4. Extract out-of-scope items
5. Extract reward ranges
6. Note the Vulnerability Rating Taxonomy (VRT) category mappings
7. Map Bugcrowd priorities: P1=critical, P2=high, P3=medium, P4=low, P5=informational

Create scope.json with the same structure as above, using platform: "bugcrowd".""",
        "intigriti": f"""## Scope Fetch Instructions

Use WebFetch to retrieve the Intigriti program page:

1. Fetch: `{url}`
2. Extract in-scope and out-of-scope domains
3. Extract bounty ranges by severity
4. Note any European-specific compliance requirements
5. Extract program rules and excluded vulnerability types

Create scope.json with platform: "intigriti".""",
        "immunefi": f"""## Scope Fetch Instructions

Use WebFetch to retrieve the Immunefi program page:

1. Fetch: `{url}`
2. Extract in-scope smart contracts, websites, and APIs
3. Note: Immunefi focuses on Web3/DeFi - bounties are often much higher
4. Extract reward ranges (may be in USD or crypto)
5. Extract any Proof of Concept requirements
6. Note chain/network specifications for smart contracts

Create scope.json with platform: "immunefi"."""
    }
    return instructions.get(platform, "")


def save_scope(scope_data, output_path):
    """Save scope data to JSON file."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(scope_data, f, indent=2)
    print(f"Scope saved to: {output_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  scope_parser.py <program-url-or-domain> [output-path]")
        print("  scope_parser.py --from-json <json-string> [output-path]")
        print("  scope_parser.py --detect <url>")
        sys.exit(1)

    if sys.argv[1] == "--detect":
        if len(sys.argv) < 3:
            print("Usage: scope_parser.py --detect <url>")
            sys.exit(1)
        platform, url = detect_platform(sys.argv[2])
        handle = extract_program_handle(url, platform) if platform != "raw_domain" else url
        print(f"PLATFORM={platform}")
        print(f"HANDLE={handle}")
        print(f"URL={url}")
        sys.exit(0)

    if sys.argv[1] == "--from-json":
        if len(sys.argv) < 3:
            print("Usage: scope_parser.py --from-json '<json>' [output-path]")
            sys.exit(1)
        try:
            scope_data = json.loads(sys.argv[2])
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON: {e}", file=sys.stderr)
            sys.exit(1)
        output_path = sys.argv[3] if len(sys.argv) > 3 else "scope.json"
        save_scope(scope_data, output_path)
        sys.exit(0)

    url_or_domain = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "scope.json"

    platform, url = detect_platform(url_or_domain)

    if platform == "raw_domain":
        scope = parse_raw_domain(url)
        save_scope(scope, output_path)
        print(f"\nRaw domain scope created for: {url}")
        print("IMPORTANT: Review and confirm scope before proceeding.")
        print(json.dumps(scope, indent=2))
    else:
        handle = extract_program_handle(url, platform)
        print(f"Platform: {platform}")
        print(f"Program: {handle}")
        print(f"URL: {url}")
        print("")
        instructions = generate_fetch_instructions(platform, url, handle)
        print(instructions)
        # Also create a minimal template that Claude will fill in
        template = create_scope_template(handle, platform)
        template["program_url"] = url
        template_path = output_path.replace(".json", "-template.json")
        save_scope(template, template_path)
        print(f"\nTemplate created at: {template_path}")
        print("Claude should fill in the scope data after fetching the program page.")


if __name__ == "__main__":
    main()
