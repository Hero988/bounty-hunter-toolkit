#!/usr/bin/env python3
"""
Authentication manager for bounty-hunter-toolkit.
Multi-layered approach to obtain authenticated sessions automatically.

Layer 1: Extract cookies from user's existing browser sessions (zero effort)
Layer 2: Use Playwright headless browser to automate login
Layer 3: Use hardcoded tokens found during APK analysis
Layer 4: Use curl cookie jar with user-provided credentials
Layer 5 (fallback): Guide user to log in once, then extract cookies

Outputs a cookies.json file that can be used by curl and Playwright.
"""

import glob
import json
import os
import platform
import subprocess
import sys
import time

HOME = os.path.expanduser("~")
IS_WINDOWS = platform.system().lower() == "windows"
PYTHON_CMD = "python" if IS_WINDOWS else "python3"


def run_cmd(cmd, timeout=30):
    """Run a command and return (success, output)."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, (result.stdout or "") + (result.stderr or "")
    except Exception as e:
        return False, str(e)


# ============================================================
# Layer 1: Extract cookies from existing browser sessions
# ============================================================

def try_browser_cookie3(domain):
    """Try to extract cookies using browser_cookie3."""
    try:
        import browser_cookie3
    except ImportError:
        # Try to install it
        success, _ = run_cmd(f"{PYTHON_CMD} -m pip install browser_cookie3 --quiet")
        if not success:
            return None, "browser_cookie3 not available"
        try:
            import browser_cookie3
        except ImportError:
            return None, "browser_cookie3 install failed"

    cookies = []
    # Try browsers in order of preference
    browsers = [
        ("firefox", browser_cookie3.firefox),
        ("chrome", browser_cookie3.chrome),
        ("edge", browser_cookie3.edge),
        ("brave", browser_cookie3.brave),
    ]
    for name, func in browsers:
        try:
            cj = func(domain_name=domain)
            for cookie in cj:
                if domain in cookie.domain:
                    cookies.append({
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "secure": cookie.secure,
                        "httpOnly": getattr(cookie, "http_only", False),
                        "source": f"browser:{name}"
                    })
            if cookies:
                return cookies, f"Extracted {len(cookies)} cookies from {name}"
        except Exception as e:
            continue

    return None, "No cookies found in any browser"


def try_rookiepy(domain):
    """Try to extract cookies using rookiepy (Rust-based, faster)."""
    try:
        import rookiepy
    except ImportError:
        success, _ = run_cmd(f"{PYTHON_CMD} -m pip install rookiepy --quiet")
        if not success:
            return None, "rookiepy not available"
        try:
            import rookiepy
        except ImportError:
            return None, "rookiepy install failed"

    cookies = []
    browsers = ["firefox", "chrome", "edge", "brave", "chromium"]
    for name in browsers:
        try:
            func = getattr(rookiepy, name, None)
            if not func:
                continue
            raw = func(domains=[domain])
            for cookie in raw:
                cookies.append({
                    "name": cookie.get("name", ""),
                    "value": cookie.get("value", ""),
                    "domain": cookie.get("domain", ""),
                    "path": cookie.get("path", "/"),
                    "secure": cookie.get("secure", False),
                    "httpOnly": cookie.get("httponly", False),
                    "source": f"browser:{name}"
                })
            if cookies:
                return cookies, f"Extracted {len(cookies)} cookies from {name} via rookiepy"
        except Exception:
            continue

    return None, "No cookies found via rookiepy"


def extract_browser_cookies(domain):
    """Layer 1: Try all browser cookie extraction methods."""
    # Try rookiepy first (Rust-based, often more reliable)
    cookies, msg = try_rookiepy(domain)
    if cookies:
        return cookies, msg

    # Fall back to browser_cookie3
    cookies, msg = try_browser_cookie3(domain)
    if cookies:
        return cookies, msg

    return None, "No browser cookies found for this domain"


# ============================================================
# Layer 2: Playwright headless browser automation
# ============================================================

def check_playwright_installed():
    """Check if Playwright is available."""
    success, _ = run_cmd("npx playwright --version", timeout=15)
    return success


def generate_playwright_login_script(url, output_state_file):
    """Generate a Playwright script for interactive login with state saving."""
    return f'''
const {{ chromium }} = require('playwright');

(async () => {{
  const browser = await chromium.launch({{
    headless: false,  // Show browser so user can log in
    slowMo: 100
  }});
  const context = await browser.newContext();
  const page = await context.newPage();

  console.log('Opening login page...');
  console.log('Please log in manually. The browser will close automatically after login is detected.');
  await page.goto('{url}');

  // Wait for navigation away from login page (indicates successful login)
  // Or wait for specific cookies/elements that indicate logged-in state
  try {{
    await page.waitForURL('**/*', {{ timeout: 300000 }}); // 5 min timeout
    // Wait a bit for all cookies to be set
    await page.waitForTimeout(3000);
  }} catch (e) {{
    console.log('Timeout waiting for login.');
  }}

  // Save authentication state
  const state = await context.storageState();
  const fs = require('fs');
  fs.writeFileSync('{output_state_file}', JSON.stringify(state, null, 2));
  console.log('AUTH_STATE_SAVED=' + '{output_state_file}');

  // Also extract cookies in our format
  const cookies = await context.cookies();
  const formatted = cookies.map(c => ({{
    name: c.name,
    value: c.value,
    domain: c.domain,
    path: c.path,
    secure: c.secure,
    httpOnly: c.httpOnly,
    source: 'playwright:interactive'
  }}));
  fs.writeFileSync('{output_state_file}'.replace('.json', '-cookies.json'), JSON.stringify(formatted, null, 2));
  console.log('COOKIES_SAVED=' + '{output_state_file}'.replace('.json', '-cookies.json'));

  await browser.close();
}})();
'''


def generate_playwright_headless_script(url, output_state_file):
    """Generate a stealth Playwright script for headless cookie extraction."""
    return f'''
const {{ chromium }} = require('playwright');

(async () => {{
  const browser = await chromium.launch({{
    headless: true,
    args: ['--disable-blink-features=AutomationControlled']
  }});
  const context = await browser.newContext({{
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  }});
  const page = await context.newPage();

  // Navigate and check if already logged in (via existing cookies)
  await page.goto('{url}');
  await page.waitForTimeout(3000);

  // Extract whatever cookies we can
  const cookies = await context.cookies();
  if (cookies.length > 0) {{
    const fs = require('fs');
    const formatted = cookies.map(c => ({{
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      source: 'playwright:headless'
    }}));
    fs.writeFileSync('{output_state_file}', JSON.stringify(formatted, null, 2));
    console.log('COOKIES_EXTRACTED=' + cookies.length);
  }} else {{
    console.log('NO_COOKIES_FOUND');
  }}

  await browser.close();
}})();
'''


# ============================================================
# Layer 3: Use tokens from APK analysis
# ============================================================

def find_apk_tokens(hunt_dir):
    """Search APK analysis results for usable tokens."""
    tokens = []
    patterns = [
        os.path.join(hunt_dir, "apk-analysis", "findings.json"),
        os.path.join(hunt_dir, "apk-analysis", "**", "findings.json"),
        os.path.join(hunt_dir, "apk-analysis", "**", "SECURITY_FINDINGS.md"),
    ]
    for pattern in patterns:
        for filepath in glob.glob(pattern, recursive=True):
            try:
                if filepath.endswith(".json"):
                    with open(filepath) as f:
                        data = json.load(f)
                    # Look for secrets/tokens in findings
                    secrets = data.get("secrets", [])
                    if isinstance(secrets, list):
                        for s in secrets:
                            if isinstance(s, dict):
                                tokens.append({
                                    "type": s.get("type", "unknown"),
                                    "value": s.get("value", s.get("match", "")),
                                    "file": s.get("file", ""),
                                    "source": "apk_analysis"
                                })
                            elif isinstance(s, str):
                                tokens.append({"type": "unknown", "value": s, "source": "apk_analysis"})
            except Exception:
                continue

    return tokens if tokens else None


# ============================================================
# Layer 4: curl cookie jar with provided credentials
# ============================================================

def open_browser(url):
    """Open a URL in the user's default browser (not Playwright)."""
    import webbrowser
    try:
        webbrowser.open(url)
        return True
    except Exception:
        # Fallback to OS-specific commands
        if IS_WINDOWS:
            run_cmd(f'start "" "{url}"')
        elif platform.system().lower() == "darwin":
            run_cmd(f'open "{url}"')
        else:
            run_cmd(f'xdg-open "{url}"')
        return True


def parse_cookie_header(cookie_header_string, domain=""):
    """
    Parse a raw Cookie header string (from browser Network tab) into structured cookies.
    This is the most reliable method — Network tab includes HttpOnly cookies that
    document.cookie and browser_cookie3 miss.
    """
    cookies = []
    # Clean up the string
    header = cookie_header_string.strip()
    if header.lower().startswith("cookie:"):
        header = header[7:].strip()

    # Split on '; ' (semicolon + space)
    pairs = header.split("; ")
    for pair in pairs:
        pair = pair.strip()
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        cookies.append({
            "name": name,
            "value": value,
            "domain": f".{domain}" if domain else "",
            "path": "/",
            "secure": True,
            "httpOnly": name.lower() in ("sso", "sso-rw", "sid", "session", "sessionid",
                                          "connect.sid", "phpsessid", "jsessionid",
                                          "cf_clearance", "__cf_bm"),
            "source": "network_tab_paste"
        })
    return cookies


def curl_login(login_url, username, password, cookie_file, extra_data=None):
    """Attempt login via curl and save cookies."""
    data = extra_data or f"username={username}&password={password}"
    cmd = f'curl -s -c "{cookie_file}" -L -d "{data}" "{login_url}"'
    success, output = run_cmd(cmd, timeout=30)
    if success and os.path.isfile(cookie_file) and os.path.getsize(cookie_file) > 50:
        return True, f"Cookies saved to {cookie_file}"
    return False, "curl login failed"


# ============================================================
# Cookie file conversion utilities
# ============================================================

def cookies_to_curl_format(cookies, output_file):
    """Convert cookie list to Netscape cookie jar format for curl."""
    lines = ["# Netscape HTTP Cookie File"]
    for c in cookies:
        domain = c.get("domain", "")
        flag = "TRUE" if domain.startswith(".") else "FALSE"
        path = c.get("path", "/")
        secure = "TRUE" if c.get("secure") else "FALSE"
        expiry = str(int(time.time()) + 86400 * 30)  # 30 days
        name = c.get("name", "")
        value = c.get("value", "")
        lines.append(f"{domain}\t{flag}\t{path}\t{secure}\t{expiry}\t{name}\t{value}")
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as f:
        f.write("\n".join(lines) + "\n")
    return output_file


def cookies_to_header(cookies, domain=None):
    """Convert cookies to a Cookie header string for curl -H."""
    filtered = cookies
    if domain:
        filtered = [c for c in cookies if domain in c.get("domain", "")]
    pairs = [f"{c['name']}={c['value']}" for c in filtered if c.get("name") and c.get("value")]
    return "; ".join(pairs)


def save_cookies(cookies, output_file):
    """Save cookies to JSON file."""
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(cookies, f, indent=2)
    return output_file


# ============================================================
# Main orchestrator
# ============================================================

def auto_authenticate(target_domain, hunt_dir, output_dir=None):
    """
    Try all authentication layers automatically.
    Returns (cookies, auth_method, message).
    """
    output_dir = output_dir or os.path.join(hunt_dir, "auth")
    os.makedirs(output_dir, exist_ok=True)

    results = {"layers_tried": [], "success": False, "method": None, "cookies": None}

    # Layer 1: Browser cookie extraction (zero user effort)
    print("[AUTH] Layer 1: Checking existing browser sessions...")
    cookies, msg = extract_browser_cookies(target_domain)
    results["layers_tried"].append({"layer": 1, "method": "browser_cookies", "result": msg})
    if cookies:
        cookie_file = os.path.join(output_dir, "cookies.json")
        save_cookies(cookies, cookie_file)
        curl_file = os.path.join(output_dir, "cookies.txt")
        cookies_to_curl_format(cookies, curl_file)
        results["success"] = True
        results["method"] = "browser_cookies"
        results["cookies"] = cookies
        results["cookie_file"] = cookie_file
        results["curl_cookie_file"] = curl_file
        results["cookie_header"] = cookies_to_header(cookies, target_domain)
        print(f"[AUTH] SUCCESS: {msg}")
        print(f"[AUTH] Cookie file: {cookie_file}")
        print(f"[AUTH] Curl cookie jar: {curl_file}")
        save_auth_results(results, output_dir)
        return results

    # Layer 3: APK tokens (if APK analysis was done)
    print("[AUTH] Layer 3: Checking APK analysis for tokens...")
    tokens = find_apk_tokens(hunt_dir)
    results["layers_tried"].append({"layer": 3, "method": "apk_tokens", "result": f"{len(tokens)} tokens" if tokens else "none"})
    if tokens:
        token_file = os.path.join(output_dir, "apk-tokens.json")
        with open(token_file, "w") as f:
            json.dump(tokens, f, indent=2)
        results["apk_tokens"] = tokens
        results["apk_token_file"] = token_file
        print(f"[AUTH] Found {len(tokens)} tokens from APK analysis")
        # Don't mark as full success — APK tokens supplement but may not provide full auth

    # Layer 2: Open user's real browser + one-step cookie paste
    # NOTE: Playwright is NOT used for login — Cloudflare/Arkose blocks automated browsers.
    # Instead, open the user's real browser and ask for ONE copy-paste from Network tab.
    if not results["success"]:
        print("")
        print("[AUTH] No automatic cookies found (Chrome 130+ encrypts cookies on Windows).")
        print("[AUTH] FALLBACK: Open user's browser for one-time login + cookie extraction.")
        print("")
        print(f"[AUTH] ACTION REQUIRED:")
        print(f"  1. Opening {target_domain} in your default browser...")
        open_browser(f"https://{target_domain}")
        print(f"  2. Log in to {target_domain} (if not already logged in)")
        print(f"  3. Press F12 → Network tab → refresh page (F5)")
        print(f"  4. Click the first request → find 'Cookie:' in Request Headers")
        print(f"  5. Right-click the Cookie value → Copy value → Paste it here")
        print(f"  6. Then run: python auth_manager.py --parse-header '<pasted-cookie-string>' {output_dir}")
        print("")
        print("[AUTH] IMPORTANT: Copy the Cookie header from the NETWORK tab, NOT from console.")
        print("[AUTH] The Network tab includes HttpOnly cookies (SSO tokens) that document.cookie misses.")
        results["fallback_instructions"] = True
        results["browser_opened"] = True

    save_auth_results(results, output_dir)
    return results


def save_auth_results(results, output_dir):
    """Save auth results to JSON."""
    results_file = os.path.join(output_dir, "auth-results.json")
    # Remove non-serializable items
    safe = {k: v for k, v in results.items() if k != "cookies" or v is None}
    if results.get("cookies"):
        safe["cookie_count"] = len(results["cookies"])
    with open(results_file, "w") as f:
        json.dump(safe, f, indent=2)


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  auth_manager.py <target-domain> <hunt-dir>          # Auto-authenticate (try all layers)")
        print("  auth_manager.py --extract <domain> <output-dir>     # Extract browser cookies only")
        print("  auth_manager.py --parse-header '<cookie-string>' <output-dir> [domain]  # Parse Cookie header from Network tab")
        print("  auth_manager.py --open-browser <url>                # Open URL in user's default browser")
        print("  auth_manager.py --to-curl <cookies.json> <out.txt>  # Convert cookies to curl format")
        print("  auth_manager.py --header <cookies.json> [domain]    # Output Cookie header string")
        sys.exit(1)

    if sys.argv[1] == "--parse-header":
        if len(sys.argv) < 4:
            print("Usage: auth_manager.py --parse-header '<cookie-string>' <output-dir> [domain]")
            sys.exit(1)
        cookie_string = sys.argv[2]
        output_dir = sys.argv[3]
        domain = sys.argv[4] if len(sys.argv) > 4 else ""
        cookies = parse_cookie_header(cookie_string, domain)
        if cookies:
            os.makedirs(output_dir, exist_ok=True)
            cookie_file = os.path.join(output_dir, "cookies.json")
            save_cookies(cookies, cookie_file)
            curl_file = os.path.join(output_dir, "cookies.txt")
            cookies_to_curl_format(cookies, curl_file)
            header_file = os.path.join(output_dir, "cookie-header-full.txt")
            with open(header_file, "w") as f:
                f.write(cookie_string.strip())
            print(f"SUCCESS: Parsed {len(cookies)} cookies")
            print(f"JSON: {cookie_file}")
            print(f"Curl jar: {curl_file}")
            print(f"Raw header: {header_file}")
            # Show session-related cookies
            session_names = {"sso", "sso-rw", "sid", "session", "sessionid", "auth", "token",
                             "access_token", "jwt", "cf_clearance"}
            session_cookies = [c for c in cookies if c["name"].lower() in session_names or "sso" in c["name"].lower()]
            if session_cookies:
                print(f"Session cookies found: {', '.join(c['name'] for c in session_cookies)}")
        else:
            print("FAILED: Could not parse cookie string")
            sys.exit(1)

    elif sys.argv[1] == "--open-browser":
        url = sys.argv[2] if len(sys.argv) > 2 else ""
        if not url:
            print("Usage: auth_manager.py --open-browser <url>")
            sys.exit(1)
        open_browser(url)
        print(f"Opened {url} in default browser")

    elif sys.argv[1] == "--extract":
        domain = sys.argv[2] if len(sys.argv) > 2 else ""
        output_dir = sys.argv[3] if len(sys.argv) > 3 else "."
        cookies, msg = extract_browser_cookies(domain)
        if cookies:
            cookie_file = os.path.join(output_dir, "cookies.json")
            save_cookies(cookies, cookie_file)
            curl_file = os.path.join(output_dir, "cookies.txt")
            cookies_to_curl_format(cookies, curl_file)
            print(f"SUCCESS: {msg}")
            print(f"JSON: {cookie_file}")
            print(f"Curl: {curl_file}")
        else:
            print(f"FAILED: {msg}")
            sys.exit(1)

    elif sys.argv[1] == "--to-curl":
        cookies_file = sys.argv[2]
        output = sys.argv[3] if len(sys.argv) > 3 else "cookies.txt"
        with open(cookies_file) as f:
            cookies = json.load(f)
        cookies_to_curl_format(cookies, output)
        print(f"Curl cookie jar: {output}")

    elif sys.argv[1] == "--header":
        cookies_file = sys.argv[2]
        domain = sys.argv[3] if len(sys.argv) > 3 else None
        with open(cookies_file) as f:
            cookies = json.load(f)
        print(cookies_to_header(cookies, domain))

    else:
        domain = sys.argv[1]
        hunt_dir = sys.argv[2] if len(sys.argv) > 2 else "."
        results = auto_authenticate(domain, hunt_dir)
        if results["success"]:
            print(f"\nAUTH_SUCCESS=true METHOD={results['method']}")
        else:
            print(f"\nAUTH_SUCCESS=false")
            sys.exit(1)


if __name__ == "__main__":
    main()
