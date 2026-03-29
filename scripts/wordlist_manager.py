#!/usr/bin/env python3
"""
Wordlist download and management for bounty-hunter-toolkit.
Downloads individual files from SecLists rather than the full 1.5GB repo.
"""

import hashlib
import json
import os
import sys
import urllib.request

HOME = os.path.expanduser("~")
WORDLIST_DIR = os.path.join(HOME, ".bounty-hunter-data", "wordlists")
MANIFEST_FILE = os.path.join(WORDLIST_DIR, "manifest.json")

BASE_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"

ESSENTIAL_WORDLISTS = {
    "discovery": {
        "common.txt": f"{BASE_URL}/Discovery/Web-Content/common.txt",
        "raft-medium-directories.txt": f"{BASE_URL}/Discovery/Web-Content/raft-medium-directories.txt",
        "raft-large-directories.txt": f"{BASE_URL}/Discovery/Web-Content/raft-large-directories.txt",
    },
    "dns": {
        "subdomains-top5000.txt": f"{BASE_URL}/Discovery/DNS/subdomains-top1million-5000.txt",
        "subdomains-top20000.txt": f"{BASE_URL}/Discovery/DNS/subdomains-top1million-20000.txt",
        "subdomains-top110000.txt": f"{BASE_URL}/Discovery/DNS/subdomains-top1million-110000.txt",
    },
    "fuzzing": {
        "LFI-Jhaddix.txt": f"{BASE_URL}/Fuzzing/LFI/LFI-Jhaddix.txt",
        "XSS-Jhaddix.txt": f"{BASE_URL}/Fuzzing/XSS/XSS-Jhaddix.txt",
        "Generic-SQLi.txt": f"{BASE_URL}/Fuzzing/SQLi/Generic-SQLi.txt",
        "command-injection-commix.txt": f"{BASE_URL}/Fuzzing/command-injection-commix.txt",
    },
    "passwords": {
        "top-passwords-shortlist.txt": f"{BASE_URL}/Passwords/Common-Credentials/top-passwords-shortlist.txt",
    }
}


def sha256(filepath):
    """Calculate SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def download_file(url, filepath, retries=3):
    """Download a file with retry logic."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    for attempt in range(retries):
        try:
            urllib.request.urlretrieve(url, filepath)
            if os.path.isfile(filepath) and os.path.getsize(filepath) > 10:
                return True
        except Exception as e:
            if attempt == retries - 1:
                print(f"  [FAIL] {os.path.basename(filepath)}: {e}")
                return False
            import time
            time.sleep(2 ** attempt)
    return False


def load_manifest():
    """Load the wordlist manifest."""
    if os.path.isfile(MANIFEST_FILE):
        with open(MANIFEST_FILE) as f:
            return json.load(f)
    return {"files": {}}


def save_manifest(manifest):
    """Save the wordlist manifest."""
    os.makedirs(os.path.dirname(MANIFEST_FILE), exist_ok=True)
    with open(MANIFEST_FILE, "w") as f:
        json.dump(manifest, f, indent=2)


def download_essential(force=False):
    """Download all essential wordlists."""
    manifest = load_manifest()
    downloaded = 0
    skipped = 0

    for category, files in ESSENTIAL_WORDLISTS.items():
        cat_dir = os.path.join(WORDLIST_DIR, category)
        os.makedirs(cat_dir, exist_ok=True)
        print(f"\n[{category}]")

        for filename, url in files.items():
            filepath = os.path.join(cat_dir, filename)
            if os.path.isfile(filepath) and not force:
                lines = sum(1 for _ in open(filepath, errors="ignore"))
                print(f"  [OK] {filename} ({lines:,} lines)")
                skipped += 1
                continue

            print(f"  Downloading {filename}...")
            if download_file(url, filepath):
                lines = sum(1 for _ in open(filepath, errors="ignore"))
                file_hash = sha256(filepath)
                manifest["files"][filename] = {
                    "path": filepath,
                    "url": url,
                    "sha256": file_hash,
                    "lines": lines,
                    "category": category
                }
                print(f"  [OK] {filename} ({lines:,} lines)")
                downloaded += 1
            else:
                print(f"  [FAIL] {filename}")

    save_manifest(manifest)
    print(f"\nDownloaded: {downloaded}, Skipped (exists): {skipped}")


def find_wordlist(name):
    """Find a wordlist by name across all directories."""
    # Check managed wordlists
    for category, files in ESSENTIAL_WORDLISTS.items():
        for filename in files:
            if name.lower() in filename.lower():
                filepath = os.path.join(WORDLIST_DIR, category, filename)
                if os.path.isfile(filepath):
                    print(filepath)
                    return filepath

    # Check user wordlists
    user_dir = os.path.join(HOME, "wordlists")
    if os.path.isdir(user_dir):
        for root, dirs, filenames in os.walk(user_dir):
            for f in filenames:
                if name.lower() in f.lower():
                    filepath = os.path.join(root, f)
                    print(filepath)
                    return filepath

    print(f"Wordlist not found: {name}", file=sys.stderr)
    return None


def list_wordlists():
    """List all available wordlists."""
    print("Managed Wordlists:")
    for category, files in ESSENTIAL_WORDLISTS.items():
        print(f"\n  [{category}]")
        for filename in files:
            filepath = os.path.join(WORDLIST_DIR, category, filename)
            if os.path.isfile(filepath):
                lines = sum(1 for _ in open(filepath, errors="ignore"))
                print(f"    [OK] {filename} ({lines:,} lines)")
            else:
                print(f"    [--] {filename} (not downloaded)")

    user_dir = os.path.join(HOME, "wordlists")
    if os.path.isdir(user_dir):
        print(f"\nUser Wordlists ({user_dir}):")
        for f in sorted(os.listdir(user_dir)):
            if os.path.isfile(os.path.join(user_dir, f)):
                filepath = os.path.join(user_dir, f)
                lines = sum(1 for _ in open(filepath, errors="ignore"))
                print(f"    {f} ({lines:,} lines)")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  wordlist_manager.py download [--force]")
        print("  wordlist_manager.py list")
        print("  wordlist_manager.py find <name>")
        sys.exit(1)

    action = sys.argv[1]

    if action == "download":
        force = "--force" in sys.argv
        download_essential(force)
    elif action == "list":
        list_wordlists()
    elif action == "find":
        name = sys.argv[2] if len(sys.argv) > 2 else ""
        find_wordlist(name)
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()
