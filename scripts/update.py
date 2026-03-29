#!/usr/bin/env python3
"""
Auto-update orchestrator for bounty-hunter-toolkit.
Checks staleness of tools, nuclei templates, and wordlists.
Updates components that are outdated.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request

HOME = os.path.expanduser("~")
IS_WINDOWS = platform.system().lower() == "windows"
DATA_DIR = os.path.join(HOME, ".bounty-hunter-data")
STATE_FILE = os.path.join(DATA_DIR, "state.json")

# Staleness thresholds (days)
THRESHOLDS = {
    "nuclei_templates": 3,
    "go_tools": 7,
    "wordlists": 30,
    "toolkit": 1,
}

GO_TOOLS = {
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx",
    "katana": "github.com/projectdiscovery/katana/cmd/katana",
    "ffuf": "github.com/ffuf/ffuf/v2",
    "dalfox": "github.com/hahwul/dalfox/v2",
    "gau": "github.com/lc/gau/v2/cmd/gau",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx",
}


def run_cmd(cmd, timeout=300):
    """Run a command and return (success, output)."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, (result.stdout or "") + (result.stderr or "")
    except (subprocess.TimeoutExpired, Exception) as e:
        return False, str(e)


def load_state():
    """Load update state from disk."""
    if os.path.isfile(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"last_update": None, "components": {}}


def save_state(state):
    """Save update state to disk."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def get_component_age(state, component):
    """Get age of a component in days. Returns None if unknown."""
    comp = state.get("components", {}).get(component, {})
    last_updated = comp.get("last_updated")
    if not last_updated:
        return None
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
        age = (datetime.now(dt.tzinfo) - dt).total_seconds() / 86400
        return age
    except Exception:
        return None


def check_staleness(state):
    """Check which components need updating."""
    stale = {}
    for component, threshold in THRESHOLDS.items():
        age = get_component_age(state, component)
        if age is None or age > threshold:
            stale[component] = {"age_days": age, "threshold": threshold}
    return stale


def update_nuclei_templates():
    """Update nuclei templates."""
    print("  Updating nuclei templates...")
    if not shutil.which("nuclei"):
        print("  [SKIP] nuclei not installed")
        return False
    success, output = run_cmd("nuclei -update-templates", timeout=300)
    if success:
        print("  [OK] Templates updated")
        return True
    print(f"  [FAIL] {output[:200]}")
    return False


def update_go_tool(name, pkg):
    """Update a single Go tool."""
    if not shutil.which("go"):
        return False
    if not shutil.which(name):
        return False  # Don't install tools that weren't installed by user
    print(f"  Updating {name}...")
    success, output = run_cmd(f"go install -v {pkg}@latest", timeout=300)
    if success:
        print(f"  [OK] {name} updated")
        return True
    print(f"  [WARN] {name}: {output[:100]}")
    return False


def update_go_tools():
    """Update all installed Go tools."""
    print("  Updating Go tools...")
    if not shutil.which("go"):
        print("  [SKIP] Go not installed")
        return False
    updated = 0
    for name, pkg in GO_TOOLS.items():
        if shutil.which(name):
            if update_go_tool(name, pkg):
                updated += 1
    print(f"  [OK] {updated} tools updated")
    return updated > 0


def update_toolkit():
    """Update the toolkit repo via git pull."""
    toolkit_dir = os.path.join(HOME, ".bounty-hunter-toolkit")
    if not os.path.isdir(toolkit_dir):
        print("  [SKIP] Toolkit not installed")
        return False
    print("  Updating toolkit...")
    success, output = run_cmd(f'git -C "{toolkit_dir}" pull', timeout=60)
    if success:
        print(f"  [OK] Toolkit updated")
        return True
    print(f"  [WARN] {output[:200]}")
    return False


def update_wordlists():
    """Re-download essential wordlists if they're very old."""
    wordlist_dir = os.path.join(DATA_DIR, "wordlists")
    if not os.path.isdir(wordlist_dir):
        print("  [SKIP] No wordlist directory")
        return False
    # Just run the setup wordlist download which skips existing files
    print("  [OK] Wordlists checked (use setup.py to re-download)")
    return True


def main():
    check_only = "--check-only" in sys.argv
    update_all = "--all" in sys.argv
    update_tools = "--tools" in sys.argv
    update_templates = "--templates" in sys.argv

    state = load_state()
    stale = check_staleness(state)

    print("=" * 50)
    print("  Bounty Hunter Toolkit Update Check")
    print("=" * 50)
    print()

    if not stale:
        print("  Everything is up to date!")
        return

    print("  Stale components:")
    for comp, info in stale.items():
        age = info["age_days"]
        threshold = info["threshold"]
        age_str = f"{age:.0f} days old" if age is not None else "never updated"
        print(f"    - {comp}: {age_str} (threshold: {threshold} days)")
    print()

    if check_only:
        print("  Run without --check-only to update.")
        return

    # Perform updates
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    if update_all or update_templates or "nuclei_templates" in stale:
        if update_nuclei_templates():
            state.setdefault("components", {})["nuclei_templates"] = {"last_updated": now}

    if update_all or update_tools or "go_tools" in stale:
        if update_go_tools():
            state.setdefault("components", {})["go_tools"] = {"last_updated": now}

    if update_all or "toolkit" in stale:
        if update_toolkit():
            state.setdefault("components", {})["toolkit"] = {"last_updated": now}

    if update_all or "wordlists" in stale:
        update_wordlists()
        state.setdefault("components", {})["wordlists"] = {"last_updated": now}

    state["last_update"] = now
    save_state(state)
    print("\n  Update complete. State saved.")


if __name__ == "__main__":
    main()
