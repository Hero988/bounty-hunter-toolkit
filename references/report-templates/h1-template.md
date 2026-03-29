# HackerOne Report Template

## Title

`[Vuln Type] in [feature/endpoint] allows [attacker action] leading to [impact]`

Examples:
- "IDOR in /api/v2/users/{id}/documents allows unauthorized access to any user's private files"
- "Stored XSS in comment field allows session hijacking of other users"
- "SQL injection in /search endpoint allows extraction of user database"

---

## Report Body

### Summary

[1-2 sentences. What is the vulnerability, where is it, and what can an attacker do with it.]

A [vulnerability type] exists in [endpoint/feature] that allows an [authenticated/unauthenticated] attacker to [specific action]. This results in [specific impact].

### Affected Asset

- **URL/Endpoint**: `https://[target]/[path]`
- **Parameter**: `[parameter name]`
- **Asset from scope**: [select from program's scope list]

### Severity

**CVSS 3.1**: [score] ([vector string])

Justification:
- Attack Vector: [Network/Adjacent/Local] -- [because...]
- Attack Complexity: [Low/High] -- [because...]
- Privileges Required: [None/Low/High] -- [because...]
- User Interaction: [None/Required] -- [because...]
- Scope: [Unchanged/Changed] -- [because...]
- Confidentiality: [None/Low/High] -- [because...]
- Integrity: [None/Low/High] -- [because...]
- Availability: [None/Low/High] -- [because...]

### Weakness

[CWE-XXX]: [Weakness name]

Common mappings:
- XSS: CWE-79
- SQLi: CWE-89
- IDOR: CWE-639
- SSRF: CWE-918
- CSRF: CWE-352
- Open Redirect: CWE-601
- Path Traversal: CWE-22
- RCE: CWE-94
- Auth Bypass: CWE-287
- Broken Access Control: CWE-284

### Steps to Reproduce

1. Navigate to `[URL]`
2. [Authenticate as / Create account with...]
3. Intercept the request to `[endpoint]` using Burp Suite
4. Modify [parameter] from `[original value]` to `[malicious value]`
5. Forward the request
6. Observe that [specific result demonstrating the vulnerability]

**HTTP Request:**
```http
[METHOD] /[path] HTTP/2
Host: [target]
Cookie: [session cookie]
Content-Type: application/json

[request body]
```

**HTTP Response (showing vulnerability):**
```http
HTTP/2 200 OK
Content-Type: application/json

[response showing leaked data / success of exploit]
```

### Impact

[Concrete impact statement. Be specific about what data is exposed, what actions can be taken, how many users are affected.]

An attacker can exploit this vulnerability to [specific action], which would allow them to [business impact]. This affects [scope of impact -- all users / users of feature X / admin accounts].

### Supporting Material

- [Screenshot 1: showing the vulnerable request]
- [Screenshot 2: showing the successful exploitation]
- [Video: full walkthrough of exploitation] (if complex)
- [PoC script] (if automated exploitation)

### Suggested Remediation

[Brief, actionable fix recommendation.]

---

## Impact Statement Examples by Vulnerability Type

### Account Takeover
An attacker can take over any user's account by [method], gaining full access to their data, settings, and the ability to perform actions on their behalf. This affects all [N] users of the platform.

### Data Breach / IDOR
An attacker can access private [data type] belonging to any user by manipulating the [parameter] value. By iterating through [ID type], an attacker could exfiltrate [data type] for all users on the platform.

### RCE
An attacker can execute arbitrary commands on the server, potentially leading to full server compromise, access to databases, lateral movement to internal systems, and exfiltration of all stored data.

### Stored XSS
An attacker can inject persistent JavaScript that executes in the browser of any user who views [page/feature]. This can be used to steal session cookies, perform actions on behalf of victims, or redirect users to phishing pages.

### SSRF
An attacker can make the server send requests to internal resources, potentially accessing cloud metadata endpoints, internal APIs, and services not exposed to the internet. On AWS, this could lead to theft of IAM credentials.

### SQL Injection
An attacker can extract data from the database, including [specific tables/data]. Depending on database permissions, this may also allow data modification or deletion, and potentially command execution on the database server.
