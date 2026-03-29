# Intigriti Report Template

## Title

`[Vuln Type] in [endpoint/feature] enables [impact]`

Examples:
- "IDOR in /api/users/{id}/invoices enables access to any customer's billing data"
- "Stored XSS via SVG upload in profile avatar enables session hijacking"
- "SSRF in webhook URL validation enables access to internal AWS metadata"

---

## Report Body

### Target / Domain

- **Affected asset**: `[domain/app from scope]`
- **Endpoint**: `https://[target]/[path]`
- **Parameter(s)**: `[parameter name(s)]`

### Vulnerability Type

[Select from dropdown -- maps to CWE]
CWE-[XXX]: [Name]

### Severity

**CVSS 3.1 Score**: [score]
**Vector**: `CVSS:3.1/AV:[N]/AC:[L]/PR:[N]/UI:[N]/S:[U]/C:[H]/I:[H]/A:[N]`

### Description

[What is the vulnerability? Technical explanation of the root cause and how it can be exploited.]

### Steps to Reproduce

1. [Set up: create account, configure state, etc.]
2. Navigate to `[URL]`
3. [Perform action that triggers the vulnerability]
4. [Intercept/modify request if needed]
5. [Show the result]

### HTTP Evidence

**Request:**
```http
[METHOD] /[path] HTTP/2
Host: [target]
[headers]

[body]
```

**Response:**
```http
HTTP/2 [status]
[headers]

[body excerpt showing vulnerability]
```

### Proof of Concept

[Screenshots, video, or exploit script]

### Impact

[Describe the concrete impact. If personal data is involved, specify the categories of data affected.]

[If GDPR-relevant]:
This vulnerability exposes [data categories] constituting personal data under GDPR Article 4(1). Exploitation at scale could affect [N] users and would likely trigger breach notification obligations under Articles 33-34.

### Remediation Suggestion

[Actionable fix recommendation]

---

## Intigriti-Specific Notes

- Always specify GDPR data categories when personal data is involved: name, email, address, financial, health, biometric
- Include CVSS vector string -- Intigriti triagers validate the score against the vector
- Redact any real user PII in screenshots (blur or mask values)
- If the program accepts reports in languages other than English, consider adding a brief summary in the local language
