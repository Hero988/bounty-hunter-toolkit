# Bugcrowd Report Template

## Title

`[Priority] [VRT Category] in [feature/endpoint] -- [impact summary]`

Examples:
- "P1 - SQL Injection in /api/search allows full database extraction"
- "P2 - Stored XSS in user profile bio field leads to session hijacking"
- "P2 - IDOR on /api/orders/{id} exposes all customer order data"

---

## Report Body

### VRT Classification

**Category**: [Select from VRT -- e.g., "Server-Side Injection > SQL Injection"]
**Suggested Priority**: [P1/P2/P3/P4]

Justification (if suggesting priority different from VRT default):
[Explain why the actual impact warrants a different priority level]

### URL / Location

- **Endpoint**: `https://[target]/[path]`
- **Parameter**: `[parameter name]`
- **HTTP Method**: [GET/POST/PUT/DELETE]

### Description

[Technical description of the vulnerability. What it is, where it lives, and why it exists.]

### Steps to Reproduce

1. [Create account / Log in as...]
2. Navigate to `[URL]`
3. [Action]
4. Intercept request with Burp Suite (or browser dev tools)
5. [Modify parameter / Send crafted request]
6. Observe [result demonstrating the vulnerability]

### HTTP Request

```http
[METHOD] /[path] HTTP/2
Host: [target]
Cookie: [session]
Content-Type: [type]

[body]
```

### HTTP Response

```http
HTTP/2 [status]
[relevant headers]

[response body showing vulnerability]
```

### Proof of Concept

[Attach screenshots, video recording, or PoC script]

- Screenshot 1: [description]
- Screenshot 2: [description]

### Impact

[What can an attacker actually do? How does this affect the business and its users?]

### Suggested Fix

[Concise remediation recommendation]

---

## VRT Quick Reference for Common Bugs

| Finding | VRT Path | Default Priority |
|---------|----------|-----------------|
| RCE | Server-Side Injection > RCE | P1 |
| SQLi (data access) | Server-Side Injection > SQLi | P1 |
| Auth bypass | Broken Auth > Auth Bypass | P1 |
| IDOR (sensitive data) | Broken Access Control > IDOR | P2 |
| Stored XSS | XSS > Stored | P2 |
| SSRF (internal access) | Server Security Misconfig > SSRF | P2 |
| Reflected XSS | XSS > Reflected | P3 |
| CSRF (state change) | Broken Auth > CSRF | P3 |
| Open Redirect | Unvalidated Redirects | P4 |
| Info Disclosure (non-PII) | Sensitive Data Exposure | P4-P5 |
