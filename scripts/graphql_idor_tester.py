#!/usr/bin/env python3
"""
graphql_idor_tester.py - Automated GraphQL IDOR testing with two accounts.

Takes two access tokens and a list of GraphQL queries with ID parameters,
then tests each query with both tokens to detect authorization bypass.

Usage:
    graphql_idor_tester.py <endpoint> <token1> <token2> --queries <queries.json>
    graphql_idor_tester.py <endpoint> <token1> <token2> --auto-extract <decompiled-dir>

Examples:
    # Test with a queries file
    graphql_idor_tester.py https://api.target.com/graphql "$TOKEN1" "$TOKEN2" --queries queries.json

    # Auto-extract queries from decompiled APK and test
    graphql_idor_tester.py https://api.target.com/graphql "$TOKEN1" "$TOKEN2" --auto-extract ./decompiled/
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def run_graphql(endpoint, token, operation_name, query, variables, extra_headers=None):
    """Execute a GraphQL query and return the parsed response."""
    # Add operationName to URL (helps bypass some WAFs like Cloudflare)
    url = f"{endpoint}?operationName={operation_name}" if operation_name else endpoint

    cmd = [
        "curl", "-sk", "-X", "POST", url,
        "-H", "Content-Type: application/json",
        "-H", f"Authorization: Bearer {token}",
        "-H", "User-Agent: okhttp/4.9.3",
        "-H", f"Origin: https://{endpoint.split('/')[2]}",
    ]

    if extra_headers:
        for key, value in extra_headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    body = json.dumps({
        "operationName": operation_name,
        "query": query,
        "variables": variables,
    })
    cmd.extend(["-d", body])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.stdout:
            return json.loads(result.stdout)
        return None
    except Exception as e:
        return {"error": str(e)}


def extract_queries_from_apk(decompiled_dir):
    """Extract GraphQL queries from decompiled APK source code."""
    queries = []
    sources_dir = os.path.join(decompiled_dir, "sources")
    if not os.path.isdir(sources_dir):
        print(f"[!] Sources directory not found: {sources_dir}", file=sys.stderr)
        return queries

    # Pattern to match GraphQL query/mutation strings
    pattern = re.compile(r'return\s+"((?:query|mutation)\s+\w+[^"]+)"')

    for root, dirs, files in os.walk(sources_dir):
        for fname in files:
            if not fname.endswith(".java"):
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for match in pattern.finditer(content):
                    query_str = match.group(1)
                    # Extract operation name
                    op_match = re.match(r'(query|mutation)\s+(\w+)', query_str)
                    if op_match:
                        op_type = op_match.group(1)
                        op_name = op_match.group(2)

                        # Check if it takes ID parameters (IDOR candidates)
                        has_id_param = bool(re.search(r'\$\w+:\s*ID[!]?', query_str))

                        # Extract variable names and types
                        var_matches = re.findall(r'\$(\w+):\s*(\w+[!]?)', query_str)
                        variables = {name: vtype for name, vtype in var_matches}

                        queries.append({
                            "operation_name": op_name,
                            "operation_type": op_type,
                            "query": query_str,
                            "has_id_param": has_id_param,
                            "variables": variables,
                            "source_file": os.path.relpath(filepath, decompiled_dir),
                        })
            except Exception:
                continue

    return queries


def test_idor(endpoint, token1, token2, queries, user1_id=None, user2_id=None, rate_limit=2):
    """
    Test IDOR by running queries with both tokens.

    Strategy:
    1. Run query with token1 to establish baseline
    2. If the query takes a userId, inject user1's ID with token2
    3. Compare responses to detect authorization bypass
    """
    results = []

    # First, get user IDs if not provided
    if not user1_id or not user2_id:
        print("[*] Detecting user IDs via Me query...")
        me_query = "query Me { me { __typename id } }"
        r1 = run_graphql(endpoint, token1, "Me", me_query, {})
        r2 = run_graphql(endpoint, token2, "Me", me_query, {})

        if r1 and r1.get("data", {}).get("me"):
            user1_id = r1["data"]["me"].get("id", "")
            print(f"  Token1 user: {user1_id}")
        if r2 and r2.get("data", {}).get("me"):
            user2_id = r2["data"]["me"].get("id", "")
            print(f"  Token2 user: {user2_id}")

    idor_candidates = [q for q in queries if q.get("has_id_param")]
    print(f"\n[*] Testing {len(idor_candidates)} IDOR candidates...")

    for i, q in enumerate(idor_candidates):
        op_name = q["operation_name"]
        query_str = q["query"]
        variables = q.get("variables", {})

        # Build test variables - inject user1's ID into queries run by token2
        test_vars = {}
        for var_name, var_type in variables.items():
            if var_type in ("ID!", "ID"):
                if "user" in var_name.lower() or "seller" in var_name.lower():
                    test_vars[var_name] = user1_id or "1"
                else:
                    test_vars[var_name] = "1"  # Generic ID test
            elif var_type in ("String!", "String"):
                test_vars[var_name] = "test"
            elif var_type in ("Int!", "Int"):
                test_vars[var_name] = 5
            elif var_type in ("Boolean!", "Boolean"):
                test_vars[var_name] = True

        # Test with token1 (should succeed for own data)
        r1 = run_graphql(endpoint, token1, op_name, query_str, test_vars)
        time.sleep(1.0 / rate_limit)

        # Test with token2 using same IDs (IDOR test)
        r2 = run_graphql(endpoint, token2, op_name, query_str, test_vars)
        time.sleep(1.0 / rate_limit)

        # Analyze results
        r1_has_data = bool(r1 and r1.get("data") and any(v is not None for v in r1["data"].values()))
        r2_has_data = bool(r2 and r2.get("data") and any(v is not None for v in r2["data"].values()))
        r1_has_errors = bool(r1 and r1.get("errors"))
        r2_has_errors = bool(r2 and r2.get("errors"))
        r2_unauthorized = bool(r2 and any("unauthorized" in str(e).lower() or "forbidden" in str(e).lower() for e in r2.get("errors", [])))

        status = "SAFE"
        if r2_has_data and not r2_unauthorized:
            if r1_has_data:
                status = "POTENTIAL_IDOR"  # Both got data - may need manual review
            else:
                status = "SUSPICIOUS"  # Token2 got data but token1 didn't
        elif r2_unauthorized:
            status = "SAFE"  # Properly blocked
        elif r2_has_errors and not r2_has_data:
            status = "SAFE"  # Query failed

        result = {
            "operation": op_name,
            "type": q["operation_type"],
            "status": status,
            "token1_data": r1_has_data,
            "token2_data": r2_has_data,
            "token2_unauthorized": r2_unauthorized,
            "variables_tested": test_vars,
        }
        results.append(result)

        icon = {"SAFE": ".", "POTENTIAL_IDOR": "!", "SUSPICIOUS": "!!"}.get(status, "?")
        print(f"  [{icon}] {op_name}: {status}")

    # Summary
    potential = [r for r in results if r["status"] in ("POTENTIAL_IDOR", "SUSPICIOUS")]
    print(f"\n[*] Results: {len(results)} tested, {len(potential)} need review")

    return results


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    endpoint = sys.argv[1]
    token1 = sys.argv[2]
    token2 = sys.argv[3]

    queries = []

    if "--queries" in sys.argv:
        idx = sys.argv.index("--queries") + 1
        with open(sys.argv[idx], "r", encoding="utf-8") as f:
            queries = json.load(f)

    if "--auto-extract" in sys.argv:
        idx = sys.argv.index("--auto-extract") + 1
        decompiled_dir = sys.argv[idx]
        print(f"[*] Extracting queries from {decompiled_dir}...")
        queries = extract_queries_from_apk(decompiled_dir)
        print(f"[+] Extracted {len(queries)} queries ({sum(1 for q in queries if q['has_id_param'])} with ID params)")

        # Save extracted queries
        output = os.path.join(decompiled_dir, "..", "extracted-queries.json")
        with open(output, "w", encoding="utf-8") as f:
            json.dump(queries, f, indent=2)
        print(f"[+] Saved to {output}")

    if not queries:
        print("No queries to test. Use --queries or --auto-extract.")
        sys.exit(1)

    # Optional parameters
    user1_id = None
    user2_id = None
    if "--user1" in sys.argv:
        user1_id = sys.argv[sys.argv.index("--user1") + 1]
    if "--user2" in sys.argv:
        user2_id = sys.argv[sys.argv.index("--user2") + 1]

    results = test_idor(endpoint, token1, token2, queries, user1_id, user2_id)

    # Save results
    results_file = "idor-test-results.json"
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to {results_file}")


if __name__ == "__main__":
    main()
