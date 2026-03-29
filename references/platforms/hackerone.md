# HackerOne Platform Reference

## Scope Format

### Asset Types

| Type | Description | Example |
|------|-------------|---------|
| Domain | Web application | `*.target.com` |
| iOS App | Mobile app | `com.target.app` |
| Android App | Mobile app | `com.target.app` |
| API | Specific API | `api.target.com/v2/*` |
| Source Code | GitHub repo | `github.com/target/repo` |
| Hardware/IoT | Physical device | Device model specification |
| Other | Catch-all | Anything else |

### Scope Qualifiers

- **In Scope**: Test freely within rules of engagement
- **Out of Scope**: Do not test. Reports will be closed as N/A.
- **Eligible for Bounty**: In scope AND qualifies for payment
- **Not Eligible for Bounty**: In scope but informational only, no payment

Always check: some subdomains may be in scope but not eligible for bounty. Read the policy page thoroughly.

---

## Severity Taxonomy (CVSS 3.1)

HackerOne uses CVSS 3.1 for severity calculation. Programs may override with custom severity.

| Rating | CVSS Score | Typical Bounty Range |
|--------|-----------|---------------------|
| Critical | 9.0 - 10.0 | $5,000 - $50,000+ |
| High | 7.0 - 8.9 | $2,000 - $15,000 |
| Medium | 4.0 - 6.9 | $500 - $5,000 |
| Low | 0.1 - 3.9 | $100 - $1,000 |
| None | 0.0 | $0 (informative) |

### CVSS 3.1 Quick Calculator

For bug bounty, the most impactful CVSS metrics:

```
Attack Vector (AV): Network (highest) > Adjacent > Local > Physical
Attack Complexity (AC): Low (highest) > High
Privileges Required (PR): None (highest) > Low > High
User Interaction (UI): None (highest) > Required
Scope (S): Changed (highest) > Unchanged
Confidentiality (C): High > Low > None
Integrity (I): High > Low > None
Availability (A): High > Low > None
```

**Common CVSS strings for bug bounty:**
- RCE (unauth): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` = 10.0
- SQLi (unauth, data access): `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` = 9.1
- IDOR (read other users' data): `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` = 6.5
- Stored XSS: `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` = 5.4
- Open redirect: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` = 6.1
- CSRF (state change): `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` = 4.3

---

## Report Structure

### Required Fields

1. **Title**: Clear, specific. "[Vuln Type] in [feature] allows [impact]"
2. **Severity**: Select from dropdown, provide CVSS if possible
3. **Weakness**: CWE type (e.g., CWE-79 for XSS, CWE-89 for SQLi)
4. **Asset**: Which in-scope asset is affected
5. **Description**: What the vulnerability is
6. **Steps to Reproduce**: Numbered, precise, reproducible
7. **Impact**: What an attacker can achieve
8. **Supporting Material**: Screenshots, videos, PoC code

### What Gets Marked Informative (Avoid These)

| Submission | Why Informative | How to Avoid |
|-----------|----------------|--------------|
| Missing security headers | No demonstrated impact | Only report if exploitable (e.g., missing CSP + XSS) |
| Self-XSS | Only affects the user themselves | Chain with CSRF or login CSRF |
| Theoretical vulnerabilities | No PoC | Always demonstrate the bug |
| Out of scope assets | Wrong target | Read scope carefully |
| Known/accepted risks | Program is aware | Check disclosed reports first |
| Rate limiting absence | Not a vuln by itself | Only report if leads to brute force of auth/OTP |
| SPF/DMARC/DKIM issues | Email config, usually N/A | Skip unless email spoofing has clear impact |
| Clickjacking without PoC | Missing X-Frame-Options alone is info | Show actual exploitable scenario with PoC |
| SSL/TLS configuration | Usually accepted risk | Skip unless truly exploitable (POODLE, BEAST on critical endpoint) |
| Stack traces/version disclosure | Low impact info leak | Only report if reveals actionable info (DB passwords, internal IPs) |

### Tips for Higher Acceptance Rates

1. **Read disclosed reports first**: Check the program's hacktivity for previously accepted (and rejected) report types
2. **Provide complete PoC**: Video or step-by-step with screenshots. Triager should be able to reproduce in < 5 minutes
3. **Demonstrate real impact**: Not "an attacker could..." but "this allows reading user X's private data, as shown in screenshot"
4. **One vulnerability per report**: Do not bundle unless they are part of a chain
5. **Test on your own accounts**: Never access real user data
6. **Check for duplicates**: Search hacktivity and use common sense (obvious XSS on the homepage was likely reported day one)
7. **Be responsive**: If triager asks questions, respond within 24 hours

---

## API Usage

### Programmatic Scope Checking

```bash
# Get program scope via API
curl -s "https://api.hackerone.com/v1/hackers/programs/{program_handle}" \
  -u "username:api_token" | jq '.relationships.structured_scopes.data'

# List your reports
curl -s "https://api.hackerone.com/v1/hackers/me/reports" \
  -u "username:api_token" | jq '.data[].attributes.title'

# Get program policy
curl -s "https://api.hackerone.com/v1/hackers/programs/{handle}" \
  -u "username:api_token" | jq '.attributes.policy'
```

### API Token Setup

1. Go to Settings > API Token
2. Generate token with appropriate permissions
3. Use as HTTP Basic Auth: `username:token`

---

## Response SLAs

### Platform Recommendations (Not Enforced)

| Action | Recommended SLA |
|--------|----------------|
| First response | 5 business days |
| Triage | 10 business days |
| Bounty decision | 15 business days |
| Resolution | Varies by severity |

### Reality Check

- Top programs (Google, Meta, etc.): Usually within SLA
- Mid-tier programs: 2-4 weeks for triage is normal
- Slow programs: 30-90 days is unfortunately common

**If no response after 15 business days**: Use the "Request Mediation" button. HackerOne staff will nudge the program.

---

## Bounty Table Interpretation

Programs list bounty ranges per severity. Key things to note:

- **Range means range**: "Critical: $5,000 - $20,000" means $5k is the floor, $20k requires exceptional impact
- **Impact determines position in range**: RCE on production = top of range. Self-XSS chain = bottom of range.
- **Bonuses exist**: Some programs offer bonuses for exceptional reports, chains, or during live events
- **Bounty splitting**: If two researchers find the same bug, bounty may be split

---

## Reputation System

| Metric | How It Works |
|--------|-------------|
| Reputation | +7 for resolved, +2 for triaged, -5 for N/A, -2 for informative, -5 for spam |
| Signal | Percentage of reports that are resolved (quality metric) |
| Impact | Average severity of resolved reports |

### Reputation Thresholds

- **0-100**: New hacker, limited private invites
- **100-500**: Some private invites start appearing
- **500-2000**: Regular private invites, access to better programs
- **2000+**: Top-tier private programs, live event invitations

---

## Report Lifecycle

```
New --> Triaged --> Bounty --> Resolved --> Disclosed (optional)
 |        |
 |        +--> Needs More Info --> (respond) --> Triaged
 |
 +--> Not Applicable (closed)
 +--> Informative (closed)
 +--> Duplicate (closed)
 +--> Spam (closed, reputation hit)
```

### Handling Each State

- **Needs More Info**: Respond quickly with requested details. No response in 30 days = auto-close.
- **Duplicate**: Check if the original report was earlier. If not, politely contest.
- **Informative**: If you disagree, explain why with additional evidence. Can request mediation.
- **N/A**: Usually means out of scope or not a vulnerability. Review scope before contesting.

---

## Platform-Specific Tips

- **Hacktivity**: Always check a program's disclosed reports before testing. Learn what they accept and what they reject.
- **Collaboration**: You can invite other hackers to collaborate on a report. Useful for chains where one hunter found each piece.
- **Retesting**: Some programs allow you to request a retest after they claim to have fixed the issue. Free reputation if the fix is incomplete.
- **CVE requests**: HackerOne can assign CVEs for resolved vulnerabilities. Request via the report.
- **Disclosure**: After resolution, you can request public disclosure. Programs have 30 days to respond. Great for building your portfolio.
