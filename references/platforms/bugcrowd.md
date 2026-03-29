# Bugcrowd Platform Reference

## Vulnerability Rating Taxonomy (VRT)

Bugcrowd uses its own severity taxonomy instead of raw CVSS. The VRT maps vulnerability types to priority levels.

### Priority Levels

| Priority | Equivalent | Typical Bounty Range | Examples |
|----------|-----------|---------------------|----------|
| P1 | Critical | $5,000 - $50,000+ | RCE, SQLi with data access, auth bypass to admin |
| P2 | High | $2,000 - $10,000 | Stored XSS with session hijack, IDOR on sensitive data, SSRF to internal |
| P3 | Medium | $500 - $3,000 | Reflected XSS, CSRF on state-changing actions, info disclosure of PII |
| P4 | Low | $100 - $500 | Self-XSS (with chain), missing security headers (with impact), verbose errors |
| P5 | Informative | $0 | Best practices, theoretical issues, no demonstrated impact |

### Key VRT Categories

```
Server-Side Injection
  |- Remote Code Execution (P1)
  |- SQL Injection (P1-P2)
  |- Server-Side Template Injection (P1-P2)
  |- XML External Entity (P1-P2)
  |- Command Injection (P1)
  |- LDAP Injection (P2)

Broken Authentication and Session Management
  |- Authentication Bypass (P1)
  |- Privilege Escalation (P1-P2)
  |- Session Fixation (P3)
  |- Weak Password Policy (P4)

Cross-Site Scripting (XSS)
  |- Stored (P2 -- P1 if admin/sensitive context)
  |- Reflected (P3)
  |- DOM-based (P3)
  |- Self-XSS (P5, unless chained)

Server Security Misconfiguration
  |- Subdomain Takeover (P2-P3)
  |- Directory Listing (P4)
  |- Default Credentials (P1-P2)

Broken Access Control
  |- IDOR (P2-P3 depending on data sensitivity)
  |- Forced Browsing to Admin (P1-P2)
  |- Path Traversal (P2)

Application-Level DoS
  |- Regex DoS (P3-P4)
  |- Resource Exhaustion (P3-P4)

Sensitive Data Exposure
  |- Token/Credential in URL (P3)
  |- PII Leakage (P2-P3)
  |- Internal IP Disclosure (P5)
```

### VRT vs CVSS Disagreements

Programs may override VRT ratings. If you believe the VRT underrates your finding:
- Explain the specific impact in your report
- Reference the program's bounty table
- If the bug chains to higher impact, show the full chain

---

## Submission Format

### Report Fields

1. **Title**: `[P-level] Vuln Type in Feature - Brief Impact`
2. **URL**: Affected endpoint
3. **VRT Classification**: Select from taxonomy dropdown
4. **Severity**: Auto-populated from VRT, can be adjusted with justification
5. **Description**: Technical details of the vulnerability
6. **Steps to Reproduce**: Numbered, exact steps
7. **Proof of Concept**: Screenshots, video, HTTP requests
8. **Impact**: Business impact statement
9. **Remediation**: Suggested fix (optional but appreciated)

### Bugcrowd-Specific Submission Tips

- **VRT accuracy matters**: Selecting the wrong VRT category can delay triage. Be precise.
- **Include HTTP requests**: Raw request/response pairs from Burp are valued by triagers.
- **Video PoC for complex bugs**: Bugcrowd triagers especially appreciate video walkthroughs.
- **Suggest the priority**: If you believe the auto-assigned VRT priority is wrong, explain why.

---

## Triage Differences from HackerOne

| Aspect | HackerOne | Bugcrowd |
|--------|-----------|----------|
| Triage team | Program's own team OR H1 triage | Bugcrowd's internal triage team (for most programs) |
| Severity | CVSS 3.1 based | VRT based |
| Duplicate handling | First to report wins | First valid report, but Bugcrowd may merge |
| Communication | Direct with program | Through Bugcrowd triage as intermediary |
| Mediation | Request mediation button | Support ticket |
| Response time | Varies by program | Generally faster due to centralized triage |

### Bugcrowd Triage Specifics

- Bugcrowd has an in-house triage team (Application Security Engineers)
- They validate your report before passing to the customer
- This means: better initial response time, but you are arguing with a security professional, not a program manager
- If triager disagrees with severity, provide clear technical justification
- Triagers can and do upgrade severity if you make a good case

---

## Program Structure

### Program Types

| Type | Description |
|------|-------------|
| Bug Bounty | Standard bounty program, monetary rewards |
| Next Gen Pen Test | Time-boxed engagement, researcher team selected by Bugcrowd |
| Attack Surface Management | Ongoing monitoring, less common for individual hunters |
| VDP (Vulnerability Disclosure) | No monetary reward, recognition only |

### Program Pages

- **Brief**: Overview, scope, rules of engagement
- **Scope**: Detailed target list with in/out of scope
- **Rewards**: Bounty table by priority level
- **Hall of Fame**: Previous successful reporters
- **Activity**: Recent submissions and trends

---

## Reputation System

### Key Metrics

| Metric | Description |
|--------|-------------|
| Points | Earned from accepted submissions, weighted by severity |
| Accuracy | Percentage of valid submissions (target > 70%) |
| Rank | Global leaderboard position |
| Kudos | Given by programs for quality reports |

### Earning Points

- P1 accepted: 40 points
- P2 accepted: 20 points
- P3 accepted: 10 points
- P4 accepted: 5 points
- Rejected/duplicate: 0 points (but accuracy drops)

### Levels and Invites

Higher accuracy and points unlock private program invitations. Maintaining high accuracy (>70%) is more important than volume on Bugcrowd.

---

## Practical Tips

- **Read the brief carefully**: Bugcrowd briefs often contain specific testing instructions and out-of-scope items that differ from the scope list
- **Use the Bugcrowd University**: Free training resources, but more importantly, completing courses may unlock private invites
- **Duplicate window**: Bugcrowd typically has a shorter duplicate window than HackerOne. Submit quickly if you find something.
- **Retesting**: Some programs offer paid retesting. If the fix is incomplete, report it as a new submission referencing the original.
- **Crowdstream**: Bugcrowd's activity feed shows anonymized recent submissions. Use it to gauge program activity.
- **Do not spray and pray**: Accuracy matters more on Bugcrowd than HackerOne. One P2 is better than five P5s.
