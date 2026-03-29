#!/usr/bin/env python3
"""
Deterministic scope enforcement for bug bounty hunting.
All scope checks are code-based (not LLM-based) for safety.
Deny-list is checked BEFORE allow-list. Empty/malformed input returns False.
"""

import json
import os
import sys
import ipaddress
from urllib.parse import urlparse


def load_scope(scope_path):
    """Load scope.json and return parsed scope data."""
    if not os.path.isfile(scope_path):
        print(f"ERROR: Scope file not found: {scope_path}", file=sys.stderr)
        return None
    with open(scope_path, "r") as f:
        return json.load(f)


def normalize_hostname(hostname):
    """Normalize a hostname for comparison."""
    if not hostname or not isinstance(hostname, str):
        return ""
    hostname = hostname.lower().strip().rstrip(".")
    # Strip port if present
    if ":" in hostname and not hostname.startswith("["):
        hostname = hostname.rsplit(":", 1)[0]
    return hostname


def extract_hostname(target):
    """Extract hostname from a URL or bare hostname."""
    if not target or not isinstance(target, str):
        return "", ""
    target = target.strip()
    # If it looks like a URL, parse it
    if "://" in target:
        parsed = urlparse(target)
        return normalize_hostname(parsed.hostname or ""), parsed.path or "/"
    # If it has a path component
    if "/" in target:
        parts = target.split("/", 1)
        return normalize_hostname(parts[0]), "/" + parts[1]
    return normalize_hostname(target), "/"


def is_ip(value):
    """Check if value is an IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def matches_cidr(ip_str, cidr_str):
    """Check if an IP matches a CIDR range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr_str, strict=False)
        return ip in network
    except ValueError:
        return False


def matches_wildcard(hostname, pattern):
    """
    Check if hostname matches a wildcard pattern.
    Uses anchored suffix matching to prevent evil-target.com matching *.target.com.

    *.example.com matches sub.example.com, a.b.example.com
    *.example.com does NOT match example.com itself
    *.example.com does NOT match evil-example.com
    """
    if not hostname or not pattern:
        return False

    hostname = normalize_hostname(hostname)
    pattern = pattern.lower().strip()

    # Exact match
    if hostname == pattern:
        return True

    # Wildcard matching
    if pattern.startswith("*."):
        base_domain = pattern[2:]  # Remove "*."
        # Must end with .base_domain (anchored suffix match)
        # This prevents evil-example.com from matching *.example.com
        if hostname == base_domain:
            return False  # *.example.com does NOT match example.com
        if hostname.endswith("." + base_domain):
            return True
        return False

    return False


def matches_path(request_path, scope_path):
    """Check if a request path matches a scope path restriction."""
    if not scope_path or scope_path == "/":
        return True  # No path restriction
    request_path = request_path or "/"
    # Normalize: ensure leading slash, strip trailing slash
    if not request_path.startswith("/"):
        request_path = "/" + request_path
    if not scope_path.startswith("/"):
        scope_path = "/" + scope_path
    # Handle wildcard paths like /api/v2/*
    if scope_path.endswith("/*"):
        prefix = scope_path[:-2]
        return request_path.startswith(prefix)
    return request_path.startswith(scope_path)


def check_scope(target, scope_data):
    """
    Check if a target is in scope.

    Returns: (is_in_scope: bool, reason: str)

    Algorithm:
    1. Extract and normalize hostname
    2. Check out-of-scope FIRST (deny takes priority)
    3. Check in-scope
    4. Default: OUT OF SCOPE
    """
    if not target:
        return False, "Empty target"

    if not scope_data:
        return False, "No scope data loaded"

    hostname, path = extract_hostname(target)

    if not hostname:
        return False, f"Could not extract hostname from: {target}"

    out_of_scope = scope_data.get("out_of_scope", [])
    in_scope = scope_data.get("in_scope", [])

    # Step 1: Check out-of-scope FIRST (deny takes priority)
    for entry in out_of_scope:
        identifier = entry.get("identifier", "")
        if not identifier:
            continue

        # IP/CIDR check
        if is_ip(hostname) and ("/" in identifier or is_ip(identifier)):
            if "/" in identifier:
                if matches_cidr(hostname, identifier):
                    return False, f"OUT OF SCOPE: {hostname} matches denied CIDR {identifier}"
            elif hostname == identifier:
                return False, f"OUT OF SCOPE: {hostname} matches denied IP {identifier}"
            continue

        # Domain/wildcard check
        if matches_wildcard(hostname, identifier):
            return False, f"OUT OF SCOPE: {hostname} matches denied pattern {identifier}"
        if normalize_hostname(identifier) == hostname:
            return False, f"OUT OF SCOPE: {hostname} matches denied domain {identifier}"

    # Step 2: Check in-scope
    for entry in in_scope:
        identifier = entry.get("identifier", "")
        scope_path = entry.get("path", "/")
        if not identifier:
            continue

        # IP/CIDR check
        if is_ip(hostname) and ("/" in identifier or is_ip(identifier)):
            if "/" in identifier:
                if matches_cidr(hostname, identifier):
                    if matches_path(path, scope_path):
                        return True, f"IN SCOPE: {hostname} matches allowed CIDR {identifier}"
            elif hostname == identifier:
                if matches_path(path, scope_path):
                    return True, f"IN SCOPE: {hostname} matches allowed IP {identifier}"
            continue

        # Domain/wildcard check
        if matches_wildcard(hostname, identifier):
            if matches_path(path, scope_path):
                return True, f"IN SCOPE: {hostname} matches allowed pattern {identifier}"
        if normalize_hostname(identifier) == hostname:
            if matches_path(path, scope_path):
                return True, f"IN SCOPE: {hostname} matches allowed domain {identifier}"

    # Step 3: Default deny
    return False, f"OUT OF SCOPE: {hostname} does not match any in-scope entry"


def check_vuln_type(vuln_type, scope_data):
    """Check if a vulnerability type is excluded by the program."""
    excluded = scope_data.get("excluded_vuln_types", [])
    vuln_lower = vuln_type.lower().strip()
    for excl in excluded:
        if excl.lower().strip() == vuln_lower:
            return False, f"EXCLUDED: {vuln_type} is excluded by program rules"
    return True, f"ALLOWED: {vuln_type} is not excluded"


def main():
    """CLI interface for scope checking."""
    if len(sys.argv) < 3:
        print("Usage: scope_guard.py <scope.json> <target> [target2 ...]")
        print("       scope_guard.py <scope.json> --check-vuln <vuln_type>")
        sys.exit(1)

    scope_path = sys.argv[1]
    scope_data = load_scope(scope_path)

    if not scope_data:
        sys.exit(1)

    if sys.argv[2] == "--check-vuln":
        if len(sys.argv) < 4:
            print("Usage: scope_guard.py <scope.json> --check-vuln <vuln_type>")
            sys.exit(1)
        vuln_type = " ".join(sys.argv[3:])
        allowed, reason = check_vuln_type(vuln_type, scope_data)
        print(f"{'ALLOWED' if allowed else 'EXCLUDED'}: {reason}")
        sys.exit(0 if allowed else 1)

    exit_code = 0
    for target in sys.argv[2:]:
        in_scope, reason = check_scope(target, scope_data)
        status = "PASS" if in_scope else "FAIL"
        print(f"[{status}] {target} -> {reason}")
        if not in_scope:
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
