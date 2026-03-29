#!/usr/bin/env python3
"""
Health check for bounty-hunter-toolkit.
Verifies tools, templates, wordlists, network, and disk space.
"""

import glob
import json
import os
import platform
import shutil
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
IS_WINDOWS = platform.system().lower() == "windows"
DATA_DIR = os.path.join(HOME, ".bounty-hunter-data")


def run_cmd(cmd, timeout=30):
    """Run a command and return (success, output)."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, (result.stdout or "") + (result.stderr or "")
    except (subprocess.TimeoutExpired, Exception) as e:
        return False, str(e)


def check_tool(name, version_cmd=None):
    """Check if a tool is installed and optionally get its version."""
    path = shutil.which(name)
    if not path:
        return False, "not found", None
    if version_cmd:
        success, output = run_cmd(version_cmd)
        if success:
            version = output.strip().split("\n")[0][:80]
            return True, version, path
    return True, "installed", path


def check_tools(quick=False):
    """Check all required tools."""
    results = []
    core_tools = [
        ("nuclei", "nuclei -version"),
        ("subfinder", "subfinder -version"),
        ("httpx", "httpx -version"),
        ("ffuf", "ffuf -V"),
        ("katana", "katana -version"),
        ("nmap", "nmap --version"),
    ]
    extended_tools = [
        ("dalfox", "dalfox version"),
        ("gau", None),
        ("waybackurls", None),
        ("assetfinder", None),
        ("subjack", None),
        ("dnsx", "dnsx -version"),
        ("naabu", "naabu -version"),
        ("interactsh-client", "interactsh-client -version"),
    ]

    print("Core Tools:")
    for name, vcmd in core_tools:
        installed, version, path = check_tool(name, vcmd)
        status = "PASS" if installed else "FAIL"
        print(f"  [{status}] {name}: {version}")
        results.append((name, installed, "core"))

    if not quick:
        print("\nExtended Tools:")
        for name, vcmd in extended_tools:
            installed, version, path = check_tool(name, vcmd)
            status = "PASS" if installed else "WARN"
            print(f"  [{status}] {name}: {version}")
            results.append((name, installed, "extended"))

    return results


def check_nuclei_templates():
    """Check nuclei template status."""
    print("\nNuclei Templates:")
    templates_dir = os.path.join(HOME, "nuclei-templates")
    if not os.path.isdir(templates_dir):
        print("  [FAIL] Templates directory not found")
        return False

    yamls = glob.glob(os.path.join(templates_dir, "**", "*.yaml"), recursive=True)
    count = len(yamls)

    # Check age
    config_paths = [
        os.path.join(HOME, "AppData", "Roaming", "nuclei", ".templates-config.json"),  # Windows
        os.path.join(HOME, ".config", "nuclei", ".templates-config.json"),  # Linux/Mac
    ]
    version = "unknown"
    for cp in config_paths:
        if os.path.isfile(cp):
            try:
                with open(cp) as f:
                    config = json.load(f)
                version = config.get("nuclei-templates-version", "unknown")
            except Exception:
                pass
            break

    # Check directory modification time
    mtime = os.path.getmtime(templates_dir)
    age_days = (time.time() - mtime) / 86400

    if count > 10000:
        status = "PASS"
    elif count > 5000:
        status = "WARN"
    else:
        status = "FAIL"
    print(f"  [{status}] {count} templates, version {version}")

    if age_days > 7:
        print(f"  [WARN] Templates are {age_days:.0f} days old. Run: nuclei -update-templates")
    else:
        print(f"  [PASS] Templates updated {age_days:.0f} days ago")

    return count > 5000


def check_wordlists():
    """Check wordlist availability."""
    print("\nWordlists:")
    # Check multiple locations
    locations = [
        os.path.join(DATA_DIR, "wordlists"),
        os.path.join(HOME, "wordlists"),
    ]

    essential = ["common.txt", "raft-medium-directories.txt", "subdomains-top5000.txt"]
    found_dir = None
    for loc in locations:
        if os.path.isdir(loc):
            found_dir = loc
            break

    if not found_dir:
        print("  [FAIL] No wordlist directory found")
        print("         Run: python setup.py --install-missing")
        return False

    missing = []
    for wl in essential:
        filepath = os.path.join(found_dir, wl)
        if os.path.isfile(filepath):
            lines = sum(1 for _ in open(filepath, errors="ignore"))
            print(f"  [PASS] {wl} ({lines:,} lines)")
        else:
            # Check subdirectories too
            found = False
            for root, dirs, files in os.walk(found_dir):
                if wl in files:
                    filepath = os.path.join(root, wl)
                    lines = sum(1 for _ in open(filepath, errors="ignore"))
                    print(f"  [PASS] {wl} ({lines:,} lines)")
                    found = True
                    break
            if not found:
                print(f"  [WARN] {wl} not found")
                missing.append(wl)

    return len(missing) == 0


def check_network():
    """Check network connectivity."""
    print("\nNetwork:")
    targets = [("github.com", "curl -s -o /dev/null -w '%{http_code}' https://github.com")]
    for name, cmd in targets:
        success, output = run_cmd(cmd, timeout=10)
        if success and "200" in output:
            print(f"  [PASS] {name} reachable")
        else:
            print(f"  [WARN] {name} unreachable")
    return True


def check_disk_space():
    """Check available disk space."""
    print("\nDisk Space:")
    try:
        usage = shutil.disk_usage(HOME)
        free_gb = usage.free / (1024 ** 3)
        status = "PASS" if free_gb > 1 else "WARN"
        print(f"  [{status}] {free_gb:.1f} GB free")
        return free_gb > 1
    except Exception:
        print("  [WARN] Could not check disk space")
        return True


def check_toolkit():
    """Check toolkit installation."""
    print("\nToolkit:")
    toolkit_dir = os.path.join(HOME, ".bounty-hunter-toolkit")
    if os.path.isdir(toolkit_dir):
        version_file = os.path.join(toolkit_dir, "version.json")
        if os.path.isfile(version_file):
            with open(version_file) as f:
                v = json.load(f)
            print(f"  [PASS] Toolkit v{v.get('version', 'unknown')}")

            # Check age via git
            success, output = run_cmd(f'git -C "{toolkit_dir}" log -1 --format=%ci')
            if success:
                print(f"  [INFO] Last commit: {output.strip()[:19]}")
        else:
            print("  [WARN] Toolkit installed but version.json missing")
    else:
        print("  [FAIL] Toolkit not installed at ~/.bounty-hunter-toolkit/")
    return True


def main():
    quick = "--quick" in sys.argv
    json_output = "--json" in sys.argv

    print("=" * 50)
    print("  Bounty Hunter Toolkit Health Check")
    print("=" * 50)
    print()

    tool_results = check_tools(quick)

    if not quick:
        check_toolkit()
        check_nuclei_templates()
        check_wordlists()
        check_network()
        check_disk_space()

    # Summary
    core_ok = sum(1 for _, installed, tier in tool_results if installed and tier == "core")
    core_total = sum(1 for _, _, tier in tool_results if tier == "core")
    ext_ok = sum(1 for _, installed, tier in tool_results if installed and tier == "extended")
    ext_total = sum(1 for _, _, tier in tool_results if tier == "extended")

    print()
    print("=" * 50)
    print(f"  Core: {core_ok}/{core_total}  Extended: {ext_ok}/{ext_total}")
    if core_ok < core_total:
        print("  Run: python setup.py --install-missing")
    print("=" * 50)

    if json_output:
        data = {
            "core_tools": {n: i for n, i, t in tool_results if t == "core"},
            "extended_tools": {n: i for n, i, t in tool_results if t == "extended"},
            "core_ok": core_ok,
            "core_total": core_total,
        }
        print(json.dumps(data))


if __name__ == "__main__":
    main()
