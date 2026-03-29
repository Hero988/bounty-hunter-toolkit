#!/usr/bin/env python3
"""
Cross-platform setup script for bounty-hunter-toolkit.
Detects OS, installs required tools, downloads wordlists, creates directories.
Uses only Python stdlib - no external dependencies.
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import time

# --- Platform Detection ---
PLATFORM = platform.system().lower()  # "windows", "linux", "darwin"
IS_WINDOWS = PLATFORM == "windows"
IS_GITBASH = IS_WINDOWS and "MSYSTEM" in os.environ
HOME = os.path.expanduser("~")
TOOLKIT_DIR = os.path.join(HOME, ".bounty-hunter-toolkit")
GOPATH = os.environ.get("GOPATH", os.path.join(HOME, "go"))
GOBIN = os.path.join(GOPATH, "bin")
PYTHON_CMD = "python" if IS_WINDOWS else "python3"
PIP_CMD = "pip" if IS_WINDOWS else "pip3"

# --- Tool Definitions ---
TIER1_TOOLS = {
    "nuclei": {
        "go_pkg": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
        "version_cmd": "nuclei -version",
        "description": "Vulnerability scanner with 9000+ templates"
    },
    "subfinder": {
        "go_pkg": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
        "version_cmd": "subfinder -version",
        "description": "Fast passive subdomain enumeration"
    },
    "httpx": {
        "go_pkg": "github.com/projectdiscovery/httpx/cmd/httpx",
        "version_cmd": "httpx -version",
        "description": "HTTP probing and tech fingerprinting"
    },
    "ffuf": {
        "go_pkg": "github.com/ffuf/ffuf/v2@latest",
        "version_cmd": "ffuf -V",
        "description": "Web fuzzer for directory/parameter discovery"
    },
    "katana": {
        "go_pkg": "github.com/projectdiscovery/katana/cmd/katana",
        "version_cmd": "katana -version",
        "description": "Web crawler with JS analysis"
    },
    "nmap": {
        "go_pkg": None,  # Not a Go tool
        "version_cmd": "nmap --version",
        "description": "Port scanner"
    }
}

TIER2_TOOLS = {
    "dalfox": {
        "go_pkg": "github.com/hahwul/dalfox/v2",
        "version_cmd": "dalfox version",
        "description": "XSS vulnerability scanner"
    },
    "gau": {
        "go_pkg": "github.com/lc/gau/v2/cmd/gau",
        "version_cmd": "gau -version",
        "description": "URL harvesting from web archives"
    },
    "waybackurls": {
        "go_pkg": "github.com/tomnomnom/waybackurls",
        "version_cmd": None,
        "description": "Fetch URLs from Wayback Machine"
    },
    "assetfinder": {
        "go_pkg": "github.com/tomnomnom/assetfinder",
        "version_cmd": None,
        "description": "Find related domains and subdomains"
    },
    "subjack": {
        "go_pkg": "github.com/haccer/subjack",
        "version_cmd": None,
        "description": "Subdomain takeover detection"
    },
    "dnsx": {
        "go_pkg": "github.com/projectdiscovery/dnsx/cmd/dnsx",
        "version_cmd": "dnsx -version",
        "description": "Fast DNS resolver"
    },
    "naabu": {
        "go_pkg": "github.com/projectdiscovery/naabu/v2/cmd/naabu",
        "version_cmd": "naabu -version",
        "description": "Fast port scanner (requires libpcap/npcap)"
    },
    "interactsh-client": {
        "go_pkg": "github.com/projectdiscovery/interactsh/cmd/interactsh-client",
        "version_cmd": "interactsh-client -version",
        "description": "Out-of-band interaction testing"
    }
}


def run_cmd(cmd, capture=True, timeout=120):
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=capture, text=True, timeout=timeout
        )
        output = (result.stdout or "") + (result.stderr or "")
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def check_prerequisite(name, cmd):
    """Check if a prerequisite is available."""
    path = shutil.which(name)
    if path:
        success, output = run_cmd(cmd)
        return True, path, output
    return False, None, f"{name} not found"


def check_go():
    """Check Go installation."""
    available, path, output = check_prerequisite("go", "go version")
    if available:
        print(f"  [OK] Go: {output.split(chr(10))[0]}")
        return True
    print("  [FAIL] Go not installed")
    print("         Install from: https://go.dev/dl/")
    return False


def check_git():
    """Check Git installation."""
    available, path, output = check_prerequisite("git", "git --version")
    if available:
        print(f"  [OK] Git: {output.split(chr(10))[0]}")
        return True
    print("  [FAIL] Git not installed")
    return False


def check_python():
    """Check Python installation."""
    print(f"  [OK] Python: {platform.python_version()}")
    return True


def install_go_tool(name, go_pkg):
    """Install a Go tool via go install."""
    if not go_pkg:
        return False, f"{name} is not a Go tool"
    pkg = go_pkg if "@" in go_pkg else f"{go_pkg}@latest"
    print(f"  Installing {name}...")
    success, output = run_cmd(f"go install -v {pkg}", timeout=300)
    if success:
        print(f"  [OK] {name} installed")
        return True, "installed"
    print(f"  [FAIL] {name}: {output[:200]}")
    return False, output


def check_tool(name, tool_info):
    """Check if a tool is installed and return its status."""
    path = shutil.which(name)
    if path:
        version = "installed"
        if tool_info.get("version_cmd"):
            success, output = run_cmd(tool_info["version_cmd"])
            if success:
                # Extract version number from output
                for line in output.split("\n"):
                    if any(v in line.lower() for v in ["version", "current", "v2.", "v3."]):
                        version = line.strip()[:80]
                        break
        return True, version, path
    return False, "not installed", None


def setup_directories():
    """Create required directories."""
    dirs = [
        os.path.join(HOME, ".bounty-hunter-data"),
        os.path.join(HOME, ".bounty-hunter-data", "sessions"),
        os.path.join(HOME, ".bounty-hunter-data", "wordlists"),
        os.path.join(HOME, ".bounty-hunter-data", "logs"),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    print(f"  [OK] Data directory: ~/.bounty-hunter-data/")


def setup_nuclei_templates():
    """Update nuclei templates."""
    print("  Updating nuclei templates (this may take a minute)...")
    success, output = run_cmd("nuclei -update-templates", timeout=300)
    if success:
        print("  [OK] Nuclei templates updated")
        return True
    print(f"  [WARN] Template update issue: {output[:200]}")
    return False


def download_wordlists():
    """Download essential wordlists from SecLists."""
    wordlist_dir = os.path.join(HOME, ".bounty-hunter-data", "wordlists")
    os.makedirs(wordlist_dir, exist_ok=True)

    # Check if user already has wordlists
    existing = os.path.join(HOME, "wordlists")
    if os.path.isdir(existing):
        print(f"  [OK] Existing wordlists found at: {existing}")
        return True

    print("  Downloading essential wordlists...")
    base_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    wordlists = {
        "common.txt": f"{base_url}/Discovery/Web-Content/common.txt",
        "raft-medium-directories.txt": f"{base_url}/Discovery/Web-Content/raft-medium-directories.txt",
        "subdomains-top5000.txt": f"{base_url}/Discovery/DNS/subdomains-top1million-5000.txt",
        "subdomains-top20000.txt": f"{base_url}/Discovery/DNS/subdomains-top1million-20000.txt",
        "LFI-Jhaddix.txt": f"{base_url}/Fuzzing/LFI/LFI-Jhaddix.txt",
        "XSS-Jhaddix.txt": f"{base_url}/Fuzzing/XSS/XSS-Jhaddix.txt",
    }
    for filename, url in wordlists.items():
        filepath = os.path.join(wordlist_dir, filename)
        if os.path.isfile(filepath):
            continue
        success, output = run_cmd(f'curl -sL -o "{filepath}" "{url}"', timeout=60)
        if success and os.path.isfile(filepath) and os.path.getsize(filepath) > 100:
            print(f"    [OK] {filename}")
        else:
            print(f"    [WARN] Failed to download {filename}")
    return True


def save_state(results):
    """Save installation state for update.py to use."""
    state = {
        "last_setup": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": PLATFORM,
        "python_version": platform.python_version(),
        "tools": {}
    }
    for name, (installed, version, path) in results.items():
        state["tools"][name] = {
            "installed": installed,
            "version": version,
            "path": path or ""
        }
    state_path = os.path.join(HOME, ".bounty-hunter-data", "state.json")
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2)
    print(f"  [OK] State saved to: {state_path}")


def main():
    install_missing = "--install-missing" in sys.argv
    tier2 = "--tier2" in sys.argv or "--all" in sys.argv
    skip_wordlists = "--skip-wordlists" in sys.argv

    print("=" * 60)
    print("  Bounty Hunter Toolkit Setup")
    print("=" * 60)
    print(f"\n  Platform: {PLATFORM} ({'Git Bash' if IS_GITBASH else 'native'})")
    print(f"  Home: {HOME}")
    print(f"  GOPATH: {GOPATH}")
    print()

    # Prerequisites
    print("[1/6] Checking prerequisites...")
    has_go = check_go()
    check_git()
    check_python()
    print()

    # Tier 1 tools
    print("[2/6] Checking core tools (Tier 1)...")
    results = {}
    missing_tier1 = []
    for name, info in TIER1_TOOLS.items():
        installed, version, path = check_tool(name, info)
        results[name] = (installed, version, path)
        status = f"[OK] {name}: {version}" if installed else f"[MISSING] {name}: {info['description']}"
        print(f"  {status}")
        if not installed:
            missing_tier1.append(name)

    # Install missing Tier 1 tools
    if missing_tier1 and has_go and install_missing:
        print(f"\n  Installing {len(missing_tier1)} missing Tier 1 tools...")
        for name in missing_tier1:
            info = TIER1_TOOLS[name]
            if info["go_pkg"]:
                success, _ = install_go_tool(name, info["go_pkg"])
                if success:
                    installed, version, path = check_tool(name, info)
                    results[name] = (installed, version, path)
            elif name == "nmap":
                print(f"  [INFO] nmap must be installed manually:")
                if IS_WINDOWS:
                    print("         Download from: https://nmap.org/download.html")
                elif PLATFORM == "linux":
                    print("         Run: sudo apt install nmap")
                else:
                    print("         Run: brew install nmap")
    elif missing_tier1 and not install_missing:
        print(f"\n  {len(missing_tier1)} tools missing. Run with --install-missing to install them.")
    print()

    # Tier 2 tools
    print("[3/6] Checking extended tools (Tier 2)...")
    missing_tier2 = []
    for name, info in TIER2_TOOLS.items():
        installed, version, path = check_tool(name, info)
        results[name] = (installed, version, path)
        status = f"[OK] {name}: {version}" if installed else f"[--] {name}: {info['description']}"
        print(f"  {status}")
        if not installed:
            missing_tier2.append(name)

    if missing_tier2 and has_go and tier2:
        print(f"\n  Installing {len(missing_tier2)} Tier 2 tools...")
        for name in missing_tier2:
            info = TIER2_TOOLS[name]
            if info["go_pkg"]:
                success, _ = install_go_tool(name, info["go_pkg"])
                if success:
                    installed, version, path = check_tool(name, info)
                    results[name] = (installed, version, path)
    print()

    # Directories
    print("[4/6] Setting up directories...")
    setup_directories()
    print()

    # Nuclei templates
    print("[5/6] Checking nuclei templates...")
    if shutil.which("nuclei"):
        templates_dir = os.path.join(HOME, "nuclei-templates")
        if os.path.isdir(templates_dir):
            import glob
            count = len(glob.glob(os.path.join(templates_dir, "**", "*.yaml"), recursive=True))
            print(f"  [OK] {count} nuclei templates found")
            if install_missing:
                setup_nuclei_templates()
        else:
            print("  [WARN] No nuclei templates found")
            if install_missing:
                setup_nuclei_templates()
    else:
        print("  [SKIP] nuclei not installed")
    print()

    # Wordlists
    print("[6/7] Checking wordlists...")
    if not skip_wordlists:
        download_wordlists()
    else:
        print("  [SKIP] Wordlist download skipped")
    print()

    # OWASP ZAP
    print("[7/7] Checking OWASP ZAP...")
    zap_path = shutil.which("zap.sh") or shutil.which("zap")
    docker_path = shutil.which("docker")
    if zap_path:
        print(f"  [OK] ZAP found: {zap_path}")
    elif docker_path:
        print(f"  [OK] Docker found — ZAP can run via: docker run -d -p 8090:8090 owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8090")
        if install_missing:
            print("  Pulling ZAP Docker image...")
            success, output = run_cmd("docker pull owasp/zap2docker-stable", timeout=300)
            if success:
                print("  [OK] ZAP Docker image pulled")
            else:
                print(f"  [WARN] Docker pull failed: {output[:100]}")
    else:
        print("  [--] ZAP not found. Install options:")
        if IS_WINDOWS:
            print("       Download: https://www.zaproxy.org/download/")
            print("       Or install Docker Desktop: https://www.docker.com/products/docker-desktop/")
        elif PLATFORM == "linux":
            print("       Run: sudo snap install zaproxy --classic")
            print("       Or: sudo apt install zaproxy")
            print("       Or: docker pull owasp/zap2docker-stable")
        else:
            print("       Run: brew install --cask zap")
            print("       Or: docker pull owasp/zap2docker-stable")
    # Install zaproxy Python client
    success, _ = run_cmd(f"{PYTHON_CMD} -c \"import zapv2\" 2>/dev/null")
    if not success:
        print("  Installing zaproxy Python client...")
        run_cmd(f"{PIP_CMD} install zaproxy --quiet", timeout=60)
    print()

    # Save state
    save_state(results)

    # Summary
    installed_count = sum(1 for v in results.values() if v[0])
    total_count = len(results)
    print("=" * 60)
    print(f"  Setup complete: {installed_count}/{total_count} tools installed")
    if missing_tier1:
        print(f"  Missing Tier 1 (critical): {', '.join(missing_tier1)}")
    if missing_tier2 and not tier2:
        print(f"  Missing Tier 2 (optional): {', '.join(missing_tier2)}")
        print("  Run with --all to install Tier 2 tools")
    print("=" * 60)


if __name__ == "__main__":
    main()
