# Intigriti Platform Reference

## Platform Overview

Intigriti is a European-based bug bounty platform headquartered in Belgium. Primary customer base is European companies, which means GDPR considerations are front and center.

---

## Severity Taxonomy

Intigriti uses CVSS 3.1, similar to HackerOne, but with its own interpretation guidelines.

| Severity | CVSS Range | Typical Bounty |
|----------|-----------|----------------|
| Critical | 9.0 - 10.0 | EUR 5,000 - 25,000+ |
| High | 7.0 - 8.9 | EUR 1,500 - 7,500 |
| Medium | 4.0 - 6.9 | EUR 500 - 2,500 |
| Low | 0.1 - 3.9 | EUR 100 - 750 |
| None | 0.0 | EUR 0 |

Note: Bounties are typically in EUR, not USD. Account for currency when comparing across platforms.

---

## GDPR Considerations

### What This Means for Hunters

- **Do not access real user PII**: Even if an IDOR exposes personal data, do not download/store/screenshot actual user PII. Demonstrate the vulnerability exists, note the data type exposed, stop there.
- **Minimize data in PoC**: Redact any personal data in screenshots. Show field names but blur/mask values.
- **Do not exfiltrate data**: Proving data access with minimal evidence is sufficient. Downloading a database dump, even as PoC, could violate GDPR.
- **Report PII exposure clearly**: If a bug leaks PII, clearly state which categories (email, phone, address, financial) as this impacts GDPR severity assessment.
- **Data retention**: Do not retain any personal data obtained during testing beyond what is needed for the report.

### GDPR-Enhanced Impact Statements

When a vulnerability involves personal data, mention the GDPR angle in your impact statement:

```
This vulnerability exposes [data type] of [number] users, which constitutes
personal data under GDPR Article 4(1). A breach of this nature would require
notification to the supervisory authority within 72 hours per Article 33,
and potentially to affected individuals per Article 34. This could result
in administrative fines up to EUR 20 million or 4% of annual global turnover.
```

This framing resonates strongly with European companies and can influence severity assessment.

---

## Submission Format

### Report Fields

1. **Title**: Concise vulnerability description
2. **Domain/Target**: Affected asset from scope
3. **Severity**: CVSS 3.1 score with vector string
4. **Vulnerability Type**: From dropdown (maps to CWE)
5. **Description**: Technical explanation
6. **Steps to Reproduce**: Numbered steps, exact and reproducible
7. **Impact**: Business and technical impact
8. **Proof of Concept**: Screenshots, video, Burp requests
9. **Suggested Fix**: Optional but valued

### Submission Tips

- Intigriti triagers are generally technical. Write for a security engineer audience.
- Include Burp request/response pairs with annotations.
- If the bug involves multiple steps, a video walkthrough significantly speeds up triage.
- Mention GDPR impact when relevant -- this is a differentiator on Intigriti vs other platforms.

---

## Triage Process

### Flow

```
Submitted --> Triage (Intigriti team) --> Accepted / Needs Info / Closed
                                            |
                                            v
                                     Program Review --> Bounty Awarded --> Resolved
```

### Key Differences from H1/Bugcrowd

| Aspect | Intigriti | H1 | Bugcrowd |
|--------|-----------|-----|----------|
| Triage team | Intigriti internal | Varies (program or H1) | Bugcrowd internal |
| Language | English (some programs accept Dutch/French/German) | English | English |
| Response SLA | Generally 5-10 business days | Varies widely | Generally faster |
| Duplicate policy | First valid report | First to report | First valid report |
| Bounty currency | EUR | USD | USD |
| GDPR awareness | Built into triage process | Not specifically | Not specifically |

### Triage Quality

Intigriti's triage team is known for being thorough. Expect:
- Technical questions about edge cases
- Requests for additional PoC if the initial one is borderline
- Fair severity assessments (they understand the European regulatory context)
- Willingness to escalate severity if GDPR impact is demonstrated

---

## Program Structure

### Program Types

- **Public programs**: Open to all registered researchers
- **Private programs**: Invitation-only, based on platform reputation
- **Live events**: On-site and remote hacking events with bonus payouts
- **Hybrid programs**: Combination of continuous bounty and periodic pen test sprints

### Scope Format

Similar to HackerOne. Programs list:
- In-scope domains and assets
- Out-of-scope items
- Rules of engagement (rate limiting, automated scanning policies)
- Specific testing restrictions (no physical testing, no social engineering, etc.)

---

## Reputation and Leaderboard

### Metrics

| Metric | Description |
|--------|-------------|
| Reputation points | Earned from accepted reports, weighted by severity |
| Streak | Consecutive valid submissions |
| Accuracy | Ratio of valid to total submissions |
| Leaderboard rank | Global and per-program ranking |

### Earning Private Invites

- Maintain accuracy above 70%
- Submit consistent quality reports (severity matters less than quality)
- Participate in live events when possible
- Engage with the community (Intigriti has an active Discord and Twitter presence)

---

## Practical Tips

- **European business hours**: Programs are primarily European. Submit reports during EU business hours (CET/CEST) for faster initial triage.
- **Seasonal patterns**: European vacation periods (August, Christmas) slow down triage. Plan accordingly.
- **Language**: While all programs accept English, some Belgian/Dutch programs may appreciate a Dutch summary. Stick to English unless you are fluent.
- **Live events**: Intigriti runs frequent live hacking events (both virtual and in-person in Europe). These offer bounty multipliers and are excellent for networking.
- **Bug Bytes newsletter**: Intigriti publishes a weekly security newsletter. Useful for staying current on techniques, and they feature top hunters.
- **Coordinate disclosure**: Intigriti has a strong disclosure culture. Requesting disclosure after fix is well-received and builds your public profile.
- **Payment**: Payouts are via bank transfer (SEPA for EU) or PayPal. Processing can take 2-4 weeks after bounty award.
