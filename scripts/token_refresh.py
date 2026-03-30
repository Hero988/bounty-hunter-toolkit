#!/usr/bin/env python3
"""
token_refresh.py - Auto-refresh short-lived access tokens for bug bounty testing.

Stores refresh tokens and automatically obtains new access tokens when needed.
Designed for targets using JWT access/refresh token patterns.

Usage:
    token_refresh.py setup <name> <refresh-endpoint> <refresh-token> [--header "Key: Value"]
    token_refresh.py get <name>
    token_refresh.py get <name> --curl-header
    token_refresh.py list
    token_refresh.py delete <name>

Examples:
    # Setup a target with refresh token
    token_refresh.py setup whatnot https://api.whatnot.com/api/v2/refresh "eyJ..." --header "Authorization: Bearer {refresh_token}"

    # Get a fresh access token (auto-refreshes if expired)
    token_refresh.py get whatnot

    # Use in curl commands
    curl -H "Authorization: Bearer $(python token_refresh.py get whatnot)" https://api.target.com/graphql
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

DATA_DIR = os.path.join(os.path.expanduser("~"), ".bounty-hunter-data", "tokens")


def ensure_dir():
    Path(DATA_DIR).mkdir(parents=True, exist_ok=True)


def load_config(name):
    filepath = os.path.join(DATA_DIR, f"{name}.json")
    if not os.path.isfile(filepath):
        return None
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(name, config):
    ensure_dir()
    filepath = os.path.join(DATA_DIR, f"{name}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def refresh_token(config):
    """Call the refresh endpoint to get a new access token."""
    endpoint = config["refresh_endpoint"]
    refresh_tok = config["refresh_token"]
    headers = config.get("headers", {})
    body = config.get("body", {})

    # Build curl command
    cmd = ["curl", "-sk", "-X", "POST", endpoint]
    cmd.extend(["-H", "Content-Type: application/json"])

    for key, value in headers.items():
        # Replace {refresh_token} placeholder
        value = value.replace("{refresh_token}", refresh_tok)
        cmd.extend(["-H", f"{key}: {value}"])

    # Add refresh token to cookie if configured
    cookie_name = config.get("refresh_cookie_name", "")
    if cookie_name:
        cmd.extend(["-H", f"Cookie: {cookie_name}={refresh_tok}"])

    # Body
    body_str = json.dumps(body) if body else "{}"
    cmd.extend(["-d", body_str])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            print(f"ERROR: Refresh request failed (exit {result.returncode})", file=sys.stderr)
            return None

        data = json.loads(result.stdout)

        # Extract tokens using configured JSON paths
        access_path = config.get("access_token_path", "access_token.token")
        refresh_path = config.get("refresh_token_path", "refresh_token.token")
        expires_path = config.get("expires_in_path", "access_token.expires_in")

        access_token = get_nested(data, access_path)
        new_refresh = get_nested(data, refresh_path)
        expires_in = get_nested(data, expires_path) or 300

        if not access_token:
            print(f"ERROR: Could not extract access token from response", file=sys.stderr)
            print(f"Response: {result.stdout[:500]}", file=sys.stderr)
            return None

        # Update stored tokens
        config["access_token"] = access_token
        config["access_token_expires"] = time.time() + int(expires_in) - 10  # 10s buffer
        if new_refresh:
            config["refresh_token"] = new_refresh

        return access_token

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return None


def get_nested(data, path):
    """Get a nested value from a dict using dot-separated path."""
    keys = path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current


def get_access_token(name):
    """Get a valid access token, refreshing if needed."""
    config = load_config(name)
    if not config:
        print(f"ERROR: No configuration found for '{name}'. Run: token_refresh.py setup {name} ...", file=sys.stderr)
        return None

    # Check if current token is still valid
    current = config.get("access_token")
    expires = config.get("access_token_expires", 0)

    if current and time.time() < expires:
        return current

    # Need to refresh
    print(f"[*] Refreshing access token for '{name}'...", file=sys.stderr)
    token = refresh_token(config)
    if token:
        save_config(name, config)
        print(f"[+] Token refreshed (expires in {int(config.get('access_token_expires', 0) - time.time())}s)", file=sys.stderr)
    return token


def setup(name, refresh_endpoint, refresh_tok, extra_headers=None):
    """Setup a new target configuration."""
    config = {
        "name": name,
        "refresh_endpoint": refresh_endpoint,
        "refresh_token": refresh_tok,
        "headers": extra_headers or {},
        "body": {},
        "refresh_cookie_name": "",
        "access_token_path": "access_token.token",
        "refresh_token_path": "refresh_token.token",
        "expires_in_path": "access_token.expires_in",
        "access_token": None,
        "access_token_expires": 0,
        "created": time.time(),
    }
    save_config(name, config)
    print(f"[+] Configuration saved for '{name}'")

    # Try initial refresh
    token = refresh_token(config)
    if token:
        save_config(name, config)
        print(f"[+] Initial token obtained successfully")
    else:
        print(f"[!] Initial refresh failed. You may need to adjust the configuration.")
        print(f"    Config file: {os.path.join(DATA_DIR, f'{name}.json')}")


def list_configs():
    """List all saved configurations."""
    ensure_dir()
    configs = sorted(Path(DATA_DIR).glob("*.json"))
    if not configs:
        print("No configurations found.")
        return
    for cfg_path in configs:
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            name = cfg_path.stem
            endpoint = cfg.get("refresh_endpoint", "?")
            expires = cfg.get("access_token_expires", 0)
            valid = "VALID" if time.time() < expires else "EXPIRED"
            remaining = max(0, int(expires - time.time()))
            print(f"  {name}: {endpoint} [{valid}, {remaining}s remaining]")
        except Exception:
            print(f"  {cfg_path.stem}: <error reading config>")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "setup":
        if len(sys.argv) < 5:
            print("Usage: token_refresh.py setup <name> <refresh-endpoint> <refresh-token> [--header 'Key: Value']")
            sys.exit(1)
        name = sys.argv[2]
        endpoint = sys.argv[3]
        token = sys.argv[4]
        headers = {}
        i = 5
        while i < len(sys.argv):
            if sys.argv[i] == "--header" and i + 1 < len(sys.argv):
                key, _, value = sys.argv[i + 1].partition(": ")
                headers[key] = value
                i += 2
            else:
                i += 1
        setup(name, endpoint, token, headers)

    elif cmd == "get":
        if len(sys.argv) < 3:
            print("Usage: token_refresh.py get <name>", file=sys.stderr)
            sys.exit(1)
        name = sys.argv[2]
        token = get_access_token(name)
        if token:
            if "--curl-header" in sys.argv:
                print(f"Authorization: Bearer {token}")
            else:
                print(token)
        else:
            sys.exit(1)

    elif cmd == "list":
        list_configs()

    elif cmd == "delete":
        if len(sys.argv) < 3:
            print("Usage: token_refresh.py delete <name>")
            sys.exit(1)
        filepath = os.path.join(DATA_DIR, f"{sys.argv[2]}.json")
        if os.path.isfile(filepath):
            os.remove(filepath)
            print(f"[+] Deleted configuration for '{sys.argv[2]}'")
        else:
            print(f"[-] No configuration found for '{sys.argv[2]}'")

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
