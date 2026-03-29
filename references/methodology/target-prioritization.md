# Target Prioritization

## Program Selection Framework

### Scoring Matrix

Rate each program 1-5 on these factors, then multiply by weight:

| Factor | Weight | How to Evaluate |
|--------|--------|----------------|
| Scope size | 3x | More assets = more attack surface. Wildcard `*.target.com` is best. |
| Bounty table | 2x | Critical payout > $5k is worth the effort. < $500 critical = skip. |
| Response time | 3x | Check avg time to first response on platform. > 30 days = frustrating. |
| Competition | 2x | New programs get swarmed. 6-month-old programs with steady payouts = ideal. |
| Tech stack | 2x | Custom apps > SaaS platforms > WordPress sites. |
| Program maturity | 1x | Mature programs have deeper bugs. New programs have low-hanging fruit. |

**Score = SUM(rating * weight). Programs scoring > 30 are strong candidates.**

### Quick Filters (Eliminate Immediately)

- **No bounty / swag only**: Skip unless you are building reputation
- **Response time > 60 days**: Your reports will rot in the queue
- **Scope is a single mobile app only**: High effort, limited surface
- **"We reserve the right to not pay"**: Adversarial programs, avoid
- **Scope excludes everything interesting**: If auth, API, and admin are out of scope, move on

### Program Type Comparison

| Type | Pros | Cons | Best For |
|------|------|------|----------|
| Public (new, < 1 month) | Low-hanging fruit available | Massive competition, duplicate risk | Fast hunters, automation |
| Public (mature, 6+ months) | Less competition, deeper bugs valued | Easy bugs already found | Manual testers, chain builders |
| Private (invited) | Much less competition | Smaller scope, reputation needed to get invites | Consistent earners |
| VDP (no bounty) | Easy to find bugs, build reputation | No money | Building platform stats for private invites |
| Enterprise programs | Huge scope, high payouts | Slow response, complex apps | Experienced hunters |

---

## Getting Into Private Programs

### Platform Reputation Signals

**HackerOne:**
- Signal > 1.0 (aim for > 5.0)
- Impact > 5.0
- Reputation > 500
- Consistent valid reports (not volume, quality)

**Bugcrowd:**
- Accuracy > 70%
- Priority reports (P1-P3)
- Consistent activity across programs

### Fast Track Strategy

1. Start with 3-5 public programs with fast response times
2. Submit 5-10 valid reports (even low severity) to build signal
3. Accept private invites as they come
4. Focus on private programs for higher ROI
5. Keep 1-2 public programs active to maintain visibility

---

## Feature Prioritization Within a Program

### Tier 1: Test First (Highest Bug Density)

**Recently Launched Features**
- Check changelogs, blog posts, release notes, app store update history
- New features have the least security review
- Look for: new API endpoints, new UI flows, new integrations
- How to find: JS diff between versions, Wayback Machine comparison, GitHub releases

**Authentication & Authorization**
- Every auth mechanism is a high-value target
- OAuth, SSO, MFA, password reset, session management
- Role-based access control on every endpoint
- Multi-tenant isolation

**Payment & Financial Flows**
- Price manipulation, race conditions, currency confusion
- Subscription tier bypass, coupon abuse
- Direct financial impact = highest bounties

**File Upload & Processing**
- Upload endpoints, document converters, image processors
- RCE, SSRF, XSS all possible
- Often poorly validated on the server side

### Tier 2: Test Second (Good ROI)

**API Endpoints**
- REST, GraphQL, WebSocket
- IDOR, mass assignment, broken access control
- API documentation (Swagger/OpenAPI) reveals full surface area
- Undocumented endpoints found via JS analysis

**Search & Filter Features**
- SQL injection, XSS, LDAP injection
- Complex query parsers are often vulnerable
- Filter/sort parameters are frequently overlooked

**User-Generated Content**
- Comments, posts, profiles, messages
- Stored XSS, CSRF, injection
- Markdown/rich text rendering bugs

**Integration Points**
- Webhooks, OAuth connections, third-party APIs
- SSRF, token leakage, insecure deserialization
- Callback URLs are often poorly validated

### Tier 3: Test If Time Permits

**Email Features**
- Email injection, template injection
- Header injection in contact forms
- HTML email rendering XSS

**Export/Import**
- CSV injection, XXE in XML import
- SSRF in URL-based import
- Path traversal in filename handling

**Mobile App / Thick Client**
- Certificate pinning bypass, local storage
- Deeper effort, often same bugs as web API
- Only if web testing is exhausted

---

## Identifying Recently Changed Features

### Techniques

```bash
# JS file diffing (compare current vs cached versions)
# Use Wayback Machine CDX API
curl "https://web.archive.org/cdx/search/cdx?url=target.com/assets/*.js&output=json&fl=timestamp,original"

# Monitor for changes
# Use tools like VisualPing, ChangeTower, or custom scripts
# diff previous and current versions of main JS bundles

# Check public sources
# - Company blog for feature announcements
# - App store release notes
# - Twitter/social media for launch announcements
# - GitHub public repos for recent commits
# - Status pages for infrastructure changes
```

### Changelog Indicators of Vulnerable Features

- "New API endpoint for..." -- test it immediately
- "Redesigned authentication flow" -- old bypasses may work, new bugs introduced
- "Added support for file type X" -- upload validation may be incomplete
- "Integration with [third party]" -- SSRF, token leakage
- "Performance improvements to search" -- query parser changes may introduce injection
- "New user roles/permissions" -- access control bugs

---

## Time Management

### Session Planning

```
Total session: 4 hours

Option A: Wide and Shallow (new program)
  - 30 min: Recon (subdomains, tech stack, scope review)
  - 30 min: Automated scanning (nuclei, directory brute)
  - 2.5 hr: Manual testing top 5 features
  - 30 min: Report writing if findings exist

Option B: Deep Dive (familiar program)
  - 15 min: Check for new features/changes since last session
  - 3 hr: Deep manual testing on 1-2 complex features
  - 45 min: Chain building from previous low-severity findings

Option C: Automation-Heavy (large scope)
  - 1 hr: Full recon pipeline
  - 1 hr: Nuclei + custom templates
  - 1 hr: Validate and triage automated findings
  - 1 hr: Manual testing on confirmed interesting endpoints
```

### When to Move On

**Move on from a program if:**
- You have spent 8+ hours with zero findings (not even info-level)
- The program has a very slow response time and you have reports pending
- The scope is too restrictive for your skillset
- You have exhausted all Tier 1 and Tier 2 features

**Move on from a feature if:**
- You have tested all items on the checklist with no results
- You have spent 2x the allocated time budget
- Security controls are robust and consistent (not just one layer)
- The feature is low-complexity with minimal attack surface

**Do NOT move on if:**
- You found one bug -- there are likely more nearby
- You are in a complex state machine and have not explored all states
- You found information disclosure that could enable chaining
- The feature is clearly custom-built and under-tested

---

## Seasonal and Strategic Timing

### When to Hunt on Specific Programs

- **Program just launched**: First 48 hours, low-hanging fruit race. Worth it if you are fast.
- **After a major feature release**: 1-2 weeks post-launch, new code with less competition than program launch.
- **Holiday periods**: Less competition from other hunters. Good for deep dives.
- **After a breach/incident**: Company may expand scope or increase bounties. Also, similar bugs to the reported breach may exist elsewhere.

### Platform Events

- **HackerOne live hacking events**: Only if invited. High payouts, intense competition.
- **Bugcrowd Bug Bash**: Time-limited events with bonus payouts.
- **New private program invites**: Accept and test within 48 hours while scope is fresh.

---

## Target Portfolio Management

Maintain 3-5 active targets at different stages:

```
Portfolio:
1. PRIMARY: Deep-dive target (familiar, private program, complex app)
   - 50% of hunting time
   - Know the app inside out
   - Look for logic bugs, chains, race conditions

2. SECONDARY: Medium-depth target (public, good scope)
   - 30% of hunting time
   - Feature-based testing
   - API and auth focus

3. ROTATION: Fresh targets for variety
   - 20% of hunting time
   - New programs, quick recon, low-hanging fruit
   - Swap out every 2-3 weeks

Review portfolio monthly. Drop targets with no ROI. Add promising new programs.
```
