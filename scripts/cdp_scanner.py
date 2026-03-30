#!/usr/bin/env python3
"""
CDP-Based Authenticated Scanner for Cloudflare-Protected Targets

Usage:
    python cdp_scanner.py <target-domain> <output-dir> [--endpoints endpoints.txt] [--port 9222]

Prerequisites:
    - pip install playwright
    - A Chromium browser running with --remote-debugging-port=9222
    - User must be logged in to the target in that browser

How it works:
    1. Connects to the running browser via Chrome DevTools Protocol
    2. Finds a page on the target domain
    3. Intercepts network requests to capture auth headers
    4. Makes fetch() calls through the browser (bypassing Cloudflare)
    5. Outputs results as JSON

Setup:
    # Launch Edge/Chrome with debugging (keeps existing browser open):
    msedge --remote-debugging-port=9222 --user-data-dir="C:/temp/edge-debug" "https://target.com"
    # Or on macOS/Linux:
    google-chrome --remote-debugging-port=9222 --user-data-dir="/tmp/chrome-debug" "https://target.com"

    # Log in manually in the browser window, then run this script
"""

import asyncio
import json
import sys
import os
import argparse
from datetime import datetime

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[!] Install playwright: pip install playwright")
    sys.exit(1)


async def main():
    parser = argparse.ArgumentParser(description="CDP-based authenticated endpoint scanner")
    parser.add_argument("domain", help="Target domain (e.g., www.example.com)")
    parser.add_argument("output_dir", help="Directory to save results")
    parser.add_argument("--endpoints", help="File with endpoint paths (one per line)")
    parser.add_argument("--port", type=int, default=9222, help="CDP port (default: 9222)")
    parser.add_argument("--delay", type=int, default=400, help="Delay between requests in ms (default: 400)")
    parser.add_argument("--intercept", action="store_true", help="Intercept and display auth headers from existing requests")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    async with async_playwright() as p:
        print(f"[*] Connecting to browser via CDP on port {args.port}...")
        try:
            browser = await p.chromium.connect_over_cdp(f"http://localhost:{args.port}")
        except Exception as e:
            print(f"[!] Cannot connect to CDP. Is a browser running with --remote-debugging-port={args.port}?")
            print(f"[!] Error: {e}")
            sys.exit(1)

        contexts = browser.contexts
        if not contexts:
            print("[!] No browser contexts found")
            sys.exit(1)

        # Find target page
        page = None
        for ctx in contexts:
            for p_page in ctx.pages:
                if args.domain in p_page.url:
                    page = p_page
                    break
            if page:
                break

        if not page:
            print(f"[!] No page found for domain '{args.domain}'")
            print(f"[*] Available pages:")
            for ctx in contexts:
                for p_page in ctx.pages:
                    print(f"    {p_page.url}")
            sys.exit(1)

        print(f"[+] Connected to: {page.url}")

        # Intercept mode: capture auth headers from existing traffic
        if args.intercept:
            print("[*] Intercepting auth headers for 15 seconds...")
            captured = []

            async def on_request(request):
                headers = request.headers
                auth_headers = {}
                for key in ["x-api-key", "x-api-signature", "x-api-timestamp",
                            "x-api-algorithm", "authorization", "x-csrf-token",
                            "x-xsrf-token"]:
                    if key in headers:
                        auth_headers[key] = headers[key]
                if auth_headers:
                    captured.append({
                        "url": request.url[:150],
                        "method": request.method,
                        "auth_headers": auth_headers
                    })

            page.on("request", on_request)
            await page.reload()
            await asyncio.sleep(15)
            page.remove_listener("request", on_request)

            print(f"[+] Captured {len(captured)} authenticated requests")
            intercept_file = os.path.join(args.output_dir, "intercepted-auth-headers.json")
            with open(intercept_file, "w") as f:
                json.dump(captured, f, indent=2)
            print(f"[+] Saved to {intercept_file}")

            if captured:
                print("\n[+] Auth mechanism detected:")
                sample = captured[0]["auth_headers"]
                for k, v in sample.items():
                    display_val = v[:40] + "..." if len(v) > 40 else v
                    print(f"    {k}: {display_val}")
            return

        # Load endpoints
        endpoints = []
        if args.endpoints and os.path.exists(args.endpoints):
            with open(args.endpoints) as f:
                endpoints = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(f"[+] Loaded {len(endpoints)} endpoints from {args.endpoints}")
        else:
            # Default common endpoints to test
            endpoints = [
                "/api/v1/users/me", "/api/v1/user", "/api/v1/account",
                "/api/v2/users/me", "/api/v2/user", "/api/v2/account",
                "/api/v3/users/info", "/api/v3/accounts", "/api/v3/wallet",
                "/api/v4/user", "/api/v4/accounts",
                "/api/me", "/api/profile", "/api/settings",
                "/public_api/v1/request_context", "/public_api/v1/assets",
            ]
            print(f"[*] Using {len(endpoints)} default endpoints (pass --endpoints file for custom list)")

        # Test authentication
        print("[*] Testing authentication...")
        auth_result = await page.evaluate("""async () => {
            // Try common user-info endpoints
            const paths = ['/api/v3/users/info', '/api/v2/user', '/api/v1/me', '/api/me', '/api/user'];
            for (const p of paths) {
                try {
                    const r = await fetch(p + '?ts=' + Date.now(), {credentials: 'include'});
                    if (r.status === 200) return {status: 200, path: p, authenticated: true};
                    if (r.status !== 404) return {status: r.status, path: p, authenticated: false};
                } catch(e) {}
            }
            return {status: 'unknown', authenticated: 'unknown', note: 'No standard user endpoint found'};
        }""")
        print(f"[*] Auth status: {json.dumps(auth_result)}")

        # Scan endpoints
        print(f"\n[*] Scanning {len(endpoints)} endpoints...\n")
        results = []

        for ep in endpoints:
            ts = int(datetime.now().timestamp() * 1000)
            path_with_ts = ep + ("&" if "?" in ep else "?") + f"ts={ts}"

            try:
                result = await page.evaluate("""async (path) => {
                    try {
                        const r = await fetch(path, {credentials: 'include'});
                        const text = await r.text();
                        let json = null;
                        try { json = JSON.parse(text); } catch {}
                        return {status: r.status, size: text.length, body: json || text.substring(0, 500)};
                    } catch(e) {
                        return {status: 'ERROR', error: e.message};
                    }
                }""", path_with_ts)

                status = result.get("status", "?")
                size = result.get("size", 0)
                color = "\033[32m" if status == 200 else "\033[31m" if status == 401 else "\033[33m"
                print(f"  [{color}{status}\033[0m] GET {ep} ({size}b)")

                results.append({"path": ep, **result})

            except Exception as e:
                print(f"  [\033[31mERR\033[0m] GET {ep}: {e}")
                results.append({"path": ep, "status": "ERROR", "error": str(e)})

            await asyncio.sleep(args.delay / 1000)

        # Save results
        result_file = os.path.join(args.output_dir, "cdp-scan-results.json")
        with open(result_file, "w") as f:
            json.dump(results, f, indent=2)

        # Summary
        ok = len([r for r in results if r.get("status") == 200])
        denied = len([r for r in results if r.get("status") in [401, 403]])
        other = len(results) - ok - denied

        print(f"\n[+] SUMMARY: {ok} accessible | {denied} denied | {other} other | {len(results)} total")
        print(f"[+] Saved to {result_file}")

        if ok > 0:
            print("\n[+] ACCESSIBLE ENDPOINTS:")
            for r in results:
                if r.get("status") == 200 and r.get("size", 0) > 10:
                    body = r.get("body", "")
                    preview = json.dumps(body)[:120] if isinstance(body, (dict, list)) else str(body)[:120]
                    print(f"    {r['path']}: {preview}")


if __name__ == "__main__":
    asyncio.run(main())
