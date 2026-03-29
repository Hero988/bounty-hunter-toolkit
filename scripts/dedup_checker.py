#!/usr/bin/env python3
"""
Duplicate checking for bug bounty findings.
Generates search queries for Claude to check hacktivity and public disclosures.
Helps avoid wasting time on findings that will be marked duplicate.
"""

import json
import sys


def generate_search_queries(finding_type, target, component=""):
    """Generate search queries to check for duplicate reports."""
    queries = []

    # HackerOne hacktivity search
    queries.append({
        "source": "hackerone_hacktivity",
        "query": f"site:hackerone.com \"{target}\" \"{finding_type}\" disclosed",
        "purpose": "Check disclosed reports on same program"
    })

    # General vulnerability disclosure search
    queries.append({
        "source": "web_general",
        "query": f"\"{target}\" \"{finding_type}\" vulnerability writeup",
        "purpose": "Check public writeups"
    })

    # Bug bounty writeup platforms
    queries.append({
        "source": "medium_writeups",
        "query": f"site:medium.com \"{target}\" \"{finding_type}\" bug bounty",
        "purpose": "Check Medium writeups"
    })

    if component:
        queries.append({
            "source": "component_specific",
            "query": f"\"{target}\" \"{component}\" \"{finding_type}\"",
            "purpose": f"Check for same vuln in {component}"
        })

    # CVE search
    queries.append({
        "source": "cve_database",
        "query": f"\"{target}\" \"{finding_type}\" CVE",
        "purpose": "Check if this is a known CVE"
    })

    return queries


def assess_duplicate_risk(finding_type, severity, target_age="established"):
    """Assess the risk that a finding is a duplicate."""
    # Common finding types have higher duplicate risk
    high_dup_risk = [
        "missing security headers", "information disclosure",
        "csrf", "open redirect", "clickjacking",
        "ssl/tls issues", "directory listing"
    ]
    medium_dup_risk = [
        "xss", "subdomain takeover", "cors misconfiguration",
        "rate limiting bypass"
    ]
    low_dup_risk = [
        "idor", "ssrf", "sql injection", "rce",
        "authentication bypass", "business logic",
        "race condition", "prompt injection"
    ]

    finding_lower = finding_type.lower()
    for vuln in high_dup_risk:
        if vuln in finding_lower:
            return "HIGH", f"'{finding_type}' is commonly reported. Verify it hasn't been disclosed."
    for vuln in medium_dup_risk:
        if vuln in finding_lower:
            return "MEDIUM", f"'{finding_type}' is sometimes reported. Check hacktivity."
    for vuln in low_dup_risk:
        if vuln in finding_lower:
            return "LOW", f"'{finding_type}' is less commonly reported but still check."

    return "MEDIUM", "Unknown duplicate risk. Check hacktivity to be safe."


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  dedup_checker.py <finding_type> <target> [component]")
        print("  dedup_checker.py --assess <finding_type>")
        print()
        print("Examples:")
        print("  dedup_checker.py 'Reflected XSS' 'example.com' '/search'")
        print("  dedup_checker.py --assess 'Missing Security Headers'")
        sys.exit(1)

    if sys.argv[1] == "--assess":
        finding_type = " ".join(sys.argv[2:])
        risk, explanation = assess_duplicate_risk(finding_type, "medium")
        print(f"Duplicate Risk: {risk}")
        print(f"Explanation: {explanation}")
        sys.exit(0)

    finding_type = sys.argv[1]
    target = sys.argv[2]
    component = sys.argv[3] if len(sys.argv) > 3 else ""

    print(f"Checking for duplicates: {finding_type} on {target}")
    print()

    # Assess risk
    risk, explanation = assess_duplicate_risk(finding_type, "medium")
    print(f"Duplicate Risk Assessment: {risk}")
    print(f"  {explanation}")
    print()

    # Generate queries
    queries = generate_search_queries(finding_type, target, component)
    print("Search Queries (use WebSearch for each):")
    print("-" * 50)
    for q in queries:
        print(f"  [{q['source']}] {q['query']}")
        print(f"    Purpose: {q['purpose']}")
        print()

    # Output as JSON for programmatic use
    output = {
        "finding_type": finding_type,
        "target": target,
        "component": component,
        "duplicate_risk": risk,
        "explanation": explanation,
        "search_queries": queries
    }
    print("\nJSON output:")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
