#!/usr/bin/env python3
"""
wayback_analyzer.py - Historical URL Analyzer for Bug Bounty Hunting

Analyzes output from gau/waybackurls, flags interesting URLs, deduplicates,
groups by domain and pattern, and produces prioritized reports.

Usage:
    wayback_analyzer.py <urls-file> <output-dir>
    wayback_analyzer.py --summary <urls-file>

Dependencies: Python 3.7+ stdlib only.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------------------------
# URL classification rules
# ---------------------------------------------------------------------------

CATEGORIES = {
    "API Endpoint": [
        r"/api/", r"/v[0-9]+/", r"/graphql", r"/rest/", r"/rpc/", r"/ws/",
    ],
    "Admin Panel": [
        r"/admin", r"/dashboard", r"/manage", r"/panel", r"/console",
        r"/backoffice", r"/cms", r"/control",
    ],
    "PII in URL": [
        r"(?i)(?:email|ssn|password|passwd|token|secret|credit.?card|"
        r"social.?security|phone|mobile|api_?key|access_?token|auth_?token)=",
    ],
    "Internal Path": [
        r"/internal/", r"/debug/", r"/test/", r"/staging/",
        r"/dev/", r"/sandbox/", r"/private/", r"/hidden/",
    ],
    "Sensitive File": [
        r"\.\./", r"/etc/", r"\.env", r"\.git", r"\.bak", r"\.sql",
        r"\.log", r"\.conf", r"\.config", r"\.yml", r"\.yaml",
        r"\.xml", r"\.json", r"\.csv", r"\.db", r"\.sqlite",
        r"\.tar", r"\.gz", r"\.zip", r"\.dump",
    ],
    "Auth Endpoint": [
        r"/login", r"/oauth", r"/callback", r"/token", r"/auth",
        r"/signup", r"/register", r"/session", r"/sso", r"/saml",
        r"/logout", r"/forgot", r"/reset",
    ],
}

PRIORITY_ORDER = [
    "PII in URL", "Sensitive File", "Internal Path",
    "Auth Endpoint", "Admin Panel", "API Endpoint",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


def classify_url(url):
    """Return list of category names that match this URL."""
    tags = []
    for category, patterns in CATEGORIES.items():
        for pat in patterns:
            if re.search(pat, url):
                tags.append(category)
                break
    return tags


def normalize_path(path):
    """Collapse numeric/hex IDs in path segments for dedup grouping."""
    parts = path.split("/")
    normalized = []
    for part in parts:
        if re.fullmatch(r"[0-9]+", part):
            normalized.append("{id}")
        elif re.fullmatch(r"[0-9a-f]{8,}", part, re.IGNORECASE):
            normalized.append("{hex}")
        elif re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", part, re.IGNORECASE):
            normalized.append("{uuid}")
        else:
            normalized.append(part)
    return "/".join(normalized)


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def parse_urls(filepath):
    """Read and parse URL file. Returns list of parsed URL dicts."""
    urls = []
    seen = set()
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            # Basic URL validation
            if not re.match(r"https?://", raw, re.IGNORECASE):
                continue
            if raw in seen:
                continue
            seen.add(raw)
            try:
                parsed = urlparse(raw)
                urls.append({
                    "raw": raw,
                    "scheme": parsed.scheme,
                    "domain": parsed.netloc.split(":")[0].lower(),
                    "port": parsed.port,
                    "path": parsed.path,
                    "query": parsed.query,
                    "params": parse_qs(parsed.query),
                    "fragment": parsed.fragment,
                    "norm_path": normalize_path(parsed.path),
                })
            except Exception:
                continue
    return urls


def analyze(urls):
    """Classify, group, and deduplicate URLs."""
    flagged = defaultdict(list)     # category -> list of url dicts
    by_domain = defaultdict(list)   # domain -> list of url dicts
    pattern_groups = defaultdict(list)  # (domain, norm_path) -> list of raw urls

    for entry in urls:
        tags = classify_url(entry["raw"])
        entry["tags"] = tags
        by_domain[entry["domain"]].append(entry)

        key = (entry["domain"], entry["norm_path"])
        pattern_groups[key].append(entry["raw"])

        for tag in tags:
            flagged[tag].append(entry)

    # Dedup: pick one representative URL per pattern group
    deduped = {}
    for key, group_urls in pattern_groups.items():
        deduped[key] = {
            "domain": key[0],
            "pattern": key[1],
            "count": len(group_urls),
            "example": group_urls[0],
            "all_urls": group_urls if len(group_urls) <= 5 else group_urls[:5],
        }

    return {
        "flagged": dict(flagged),
        "by_domain": dict(by_domain),
        "pattern_groups": deduped,
    }


def print_summary(urls, analysis):
    """Print a quick terminal summary."""
    flagged = analysis["flagged"]
    by_domain = analysis["by_domain"]
    patterns = analysis["pattern_groups"]

    print(f"\n{'=' * 60}")
    print(f"  Wayback URL Analysis Summary")
    print(f"{'=' * 60}")
    print(f"  Total URLs (unique):  {len(urls)}")
    print(f"  Unique domains:       {len(by_domain)}")
    print(f"  Unique path patterns: {len(patterns)}")
    print()

    print("  Flagged URLs by category:")
    for cat in PRIORITY_ORDER:
        count = len(flagged.get(cat, []))
        if count:
            marker = " <<<" if cat in ("PII in URL", "Sensitive File") else ""
            print(f"    {cat:20s}  {count:>6d}{marker}")
    unflagged = sum(1 for u in urls if not u.get("tags"))
    print(f"    {'Uncategorized':20s}  {unflagged:>6d}")
    print()

    # Top domains
    top = sorted(by_domain.items(), key=lambda x: -len(x[1]))[:10]
    print("  Top domains:")
    for domain, entries in top:
        print(f"    {domain:40s}  {len(entries):>6d} URLs")
    print()


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_reports(output_dir, source_file, urls, analysis):
    """Write JSON and markdown reports."""
    ensure_dir(output_dir)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    flagged = analysis["flagged"]
    by_domain = analysis["by_domain"]
    patterns = analysis["pattern_groups"]

    # --- JSON ---
    json_data = {
        "meta": {
            "tool": "wayback_analyzer.py",
            "source": source_file,
            "timestamp": timestamp,
            "total_urls": len(urls),
            "unique_domains": len(by_domain),
            "unique_patterns": len(patterns),
        },
        "flagged": {cat: [u["raw"] for u in items] for cat, items in flagged.items()},
        "domains": {d: len(entries) for d, entries in by_domain.items()},
        "pattern_groups": [
            {"domain": v["domain"], "pattern": v["pattern"],
             "count": v["count"], "example": v["example"]}
            for v in sorted(patterns.values(), key=lambda x: -x["count"])
        ],
    }
    json_path = os.path.join(output_dir, "wayback_analysis.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)
    print(f"[+] JSON report -> {json_path}")

    # --- Markdown ---
    md_path = os.path.join(output_dir, "wayback_analysis.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Wayback URL Analysis\n\n")
        f.write(f"**Source:** `{source_file}`\n")
        f.write(f"**Generated:** {timestamp}\n")
        f.write(f"**Total unique URLs:** {len(urls)}\n")
        f.write(f"**Unique domains:** {len(by_domain)}\n\n")
        f.write("---\n\n")

        # Priority findings
        for cat in PRIORITY_ORDER:
            items = flagged.get(cat, [])
            if not items:
                continue
            f.write(f"## {cat} ({len(items)})\n\n")
            shown = items[:50]
            for u in shown:
                f.write(f"- `{u['raw']}`\n")
            if len(items) > 50:
                f.write(f"- ... and {len(items) - 50} more (see JSON)\n")
            f.write("\n")

        # Domain breakdown
        f.write("## Domains\n\n")
        f.write("| Domain | URLs | Flagged |\n")
        f.write("|--------|------|---------|\n")
        for domain, entries in sorted(by_domain.items(), key=lambda x: -len(x[1])):
            n_flagged = sum(1 for e in entries if e.get("tags"))
            f.write(f"| `{domain}` | {len(entries)} | {n_flagged} |\n")
        f.write("\n")

        # Top repeated patterns
        top_patterns = sorted(patterns.values(), key=lambda x: -x["count"])[:30]
        if top_patterns:
            f.write("## Top Repeated Path Patterns\n\n")
            for p in top_patterns:
                if p["count"] > 1:
                    f.write(f"- **{p['domain']}** `{p['pattern']}` ({p['count']}x) - e.g. `{p['example']}`\n")
            f.write("\n")

    print(f"[+] Markdown report -> {md_path}")
    return json_path, md_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze historical URLs from gau/waybackurls for bug bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s urls.txt ./output
  %(prog)s --summary urls.txt
""",
    )
    parser.add_argument("urls_file", help="File with URLs (one per line)")
    parser.add_argument("output_dir", nargs="?", default=None,
                        help="Directory for reports (required unless --summary)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary to terminal only (no files written)")

    args = parser.parse_args()

    if not os.path.isfile(args.urls_file):
        print(f"[!] File not found: {args.urls_file}")
        sys.exit(1)

    if not args.summary and not args.output_dir:
        print("[!] output_dir is required unless --summary is used.")
        sys.exit(1)

    print(f"[*] Parsing URLs from {args.urls_file} ...")
    urls = parse_urls(args.urls_file)
    if not urls:
        print("[!] No valid URLs found.")
        sys.exit(1)
    print(f"[*] Loaded {len(urls)} unique URLs.")

    print("[*] Analyzing ...")
    analysis = analyze(urls)

    print_summary(urls, analysis)

    if not args.summary:
        output_dir = os.path.abspath(args.output_dir)
        generate_reports(output_dir, args.urls_file, urls, analysis)
        print()
        print("[*] Done.")


if __name__ == "__main__":
    main()
