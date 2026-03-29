# Recon Playbook

## Quick-Reference Decision Flow

```
START
  |
  v
[Passive Recon: 15 min max]
  |-- Subdomain enumeration
  |-- Tech stack fingerprinting
  |-- Historical data (Wayback, CT logs)
  |
  v
[Evaluate Surface Area]
  |-- < 10 live hosts --> deep dive each
  |-- 10-100 live hosts --> prioritize by tech/features
  |-- 100+ live hosts --> filter aggressively, test top 20
  |
  v
[Active Recon: per-host, 5 min rule]
  |-- Port scan (top 1000 first)
  |-- Directory brute + parameter discovery
  |-- If nothing interesting in 5 min --> MOVE ON
  |-- If signal found --> extend to 15 min deep dive
  |
  v
[Catalog & Prioritize]
  |-- Rank by: auth complexity, custom code, data sensitivity
  |-- Feed into manual testing pipeline
```

---

## Phase 1: Subdomain Enumeration

### Tool Chain (run in parallel)

```bash
# Layer 1: Passive sources (run all simultaneously)
subfinder -d target.com -all -o subs_subfinder.txt
amass enum -passive -d target.com -o subs_amass.txt
assetfinder --subs-only target.com > subs_assetfinder.txt
github-subdomains -d target.com -t $GITHUB_TOKEN -o subs_github.txt

# Layer 2: Certificate transparency
crt.sh query: %.target.com
certspotter via API

# Layer 3: Brute force (only if scope is small or target is high-value)
puredns bruteforce wordlist.txt target.com -r resolvers.txt -w subs_brute.txt

# Merge and resolve
cat subs_*.txt | sort -u > all_subs.txt
puredns resolve all_subs.txt -r resolvers.txt -w resolved.txt
dnsx -l resolved.txt -a -resp -o dns_records.txt
```

### When to Brute Force

- Target has < 50 known subdomains: YES, brute force
- Target has 500+ known subdomains: passive is likely sufficient
- Wildcard DNS detected: use `puredns` with wildcard filtering
- Time-boxed engagement: skip brute force, passive only

### Wordlists

- General: `best-dns-wordlist.txt` (SecLists)
- Targeted: generate permutations with `gotator` or `altdns` from discovered subs
- Tech-specific: if target uses AWS, add `s3`, `eks`, `lambda`, `api-gateway` patterns

---

## Phase 2: HTTP Probing & Fingerprinting

```bash
# Probe for live HTTP services
httpx -l resolved.txt -ports 80,443,8080,8443,8000,3000,9090 \
  -title -status-code -tech-detect -content-length \
  -follow-redirects -o httpx_results.txt

# Screenshot for visual triage
gowitness file -f live_hosts.txt -P screenshots/

# Tech fingerprinting
nuclei -l live_hosts.txt -t technologies/ -o tech_fingerprints.txt
```

### Signal Indicators (investigate further)

- Non-standard ports (8080, 8443, 3000, 9090, 4443)
- Dev/staging subdomains: `dev.`, `staging.`, `uat.`, `preprod.`, `test.`
- API endpoints: `api.`, `api-v2.`, `graphql.`, `ws.`
- Admin panels: `admin.`, `dashboard.`, `manage.`, `internal.`
- Status codes 401/403 (something is there, access controlled)
- Unique titles (not generic "404" or company homepage)
- Low content-length with 200 status (possible empty/debug page)

### Noise Indicators (deprioritize)

- Parked domains / generic hosting pages
- CDN default pages
- Marketing sites (WordPress with no custom functionality)
- Status code 301 redirecting to main site

---

## Phase 3: Content Discovery

### Per-Host (apply 5-minute rule)

```bash
# Fast directory brute
feroxbuster -u https://target.com -w raft-medium-directories.txt \
  -t 50 --smart -o dirs.txt --auto-tune

# Parameter discovery
arjun -u https://target.com/endpoint -oJ params.json
paramspider -d target.com

# JavaScript analysis
katana -u https://target.com -js-crawl -d 3 -o crawl.txt
# Extract endpoints from JS
cat crawl.txt | grep "\.js$" | httpx -sr -srd js_files/
nuclei -l js_urls.txt -t exposures/ -t tokens/
```

### Wordlist Selection by Tech Stack

| Tech Stack     | Wordlist                           |
|----------------|------------------------------------|
| PHP            | `raft-medium-directories.txt` + `.php` extensions |
| Java/Spring    | Spring-specific wordlist, `/actuator`, `/swagger` |
| .NET           | `aspx`, `/elmah.axd`, `/trace.axd` |
| Node/Express   | `/.env`, `/package.json`, `/graphql` |
| Python/Django  | `/admin`, `/api/docs`, `/__debug__/` |
| Ruby/Rails     | `/rails/info`, `/sidekiq`, `/admin` |
| Go             | `/debug/pprof`, `/metrics`, `/health` |

---

## Phase 4: Historical & Passive Intelligence

```bash
# Wayback Machine URLs
waymore -i target.com -mode U -oU wayback_urls.txt

# Filter for interesting parameters
cat wayback_urls.txt | uro | grep -iE "(redirect|url|next|return|path|file|page|dir|search|query|id|token)" > interesting_params.txt

# Google dorking (manual or automated)
# site:target.com filetype:pdf
# site:target.com inurl:admin
# site:target.com ext:json OR ext:xml OR ext:conf
# "target.com" password OR secret OR token

# Check for leaked credentials / secrets
# Search GitHub: "target.com" password | secret | key | token
trufflehog github --org=target-org
```

### Wayback Filtering Priority

1. URLs with authentication parameters (`token=`, `session=`, `auth=`)
2. URLs with file operations (`file=`, `path=`, `dir=`, `download=`)
3. URLs with redirect parameters (`redirect=`, `url=`, `next=`, `return=`)
4. URLs with ID parameters (`id=`, `uid=`, `user_id=`)
5. API endpoints (anything with `/api/`, `/v1/`, `/v2/`)
6. Admin/internal paths

---

## Phase 5: Cloud & Infrastructure Recon

```bash
# S3 bucket enumeration
cloud_enum -k target -k targetcorp

# Check for subdomain takeover
nuclei -l resolved.txt -t takeovers/
subjack -w resolved.txt -t 100 -timeout 30 -o takeovers.txt

# IP range analysis
whois -h whois.radb.net -- '-i origin AS12345' | grep -Eo "([0-9.]+){4}/[0-9]+"
masscan -iL ip_ranges.txt -p1-65535 --rate=1000 -oJ masscan.json
```

### Cloud Misconfig Checklist

- [ ] S3 buckets: public read, public write, public list
- [ ] Azure blobs: container-level access
- [ ] GCP storage: allUsers / allAuthenticatedUsers
- [ ] Firebase: `.json` appended to database URL returns data
- [ ] Elasticsearch/Kibana exposed on subdomains
- [ ] Kubernetes dashboard without auth

---

## The 5-Minute Rule

For each host/endpoint during active recon:

1. **0-2 min**: Run directory brute, check for obvious misconfigs
2. **2-4 min**: Check response headers, error pages, tech stack
3. **4-5 min**: If no signal, STOP. Move to next host.

**Extend to 15 min if:**
- Custom application code detected (not off-the-shelf CMS)
- Authentication or authorization mechanisms present
- API endpoints discovered
- File upload or processing features found
- Non-standard error messages (stack traces, debug info)
- Admin/internal functionality detected

**Skip entirely if:**
- Static marketing site with no dynamic features
- Parked domain or redirect-only host
- CDN-served asset host (images, CSS, JS only)

---

## Asset Prioritization Matrix

| Priority | Asset Type                     | Why                                    |
|----------|-------------------------------|----------------------------------------|
| P0       | Auth endpoints, OAuth flows    | Account takeover potential              |
| P0       | Payment/billing APIs           | Financial impact                        |
| P0       | Admin panels                   | Full compromise if breached             |
| P1       | File upload endpoints          | RCE, SSRF potential                     |
| P1       | API endpoints with CRUD ops    | IDOR, broken access control             |
| P1       | GraphQL endpoints              | Over-fetching, introspection leaks      |
| P2       | Search/filter features         | SQLi, XSS                              |
| P2       | User profile/settings          | CSRF, stored XSS, IDOR                 |
| P3       | Static content, docs           | Info disclosure only                    |
| P3       | Marketing pages                | Reflected XSS at best                  |

---

## Output Format for Handoff to Testing

After recon, produce a structured catalog:

```
## Target: target.com

### High-Priority Hosts
- https://api.target.com (Node.js, JWT auth, 47 endpoints found)
- https://admin.target.com (React SPA, 403 from outside, auth bypass potential)
- https://uploads.target.com (file upload service, S3 backend)

### Discovered Parameters of Interest
- /api/v2/users?id= (IDOR candidate)
- /search?q= (reflection detected)
- /oauth/callback?redirect_uri= (open redirect candidate)

### Tech Stack Summary
- Frontend: React 18
- Backend: Node.js + Express
- Database: PostgreSQL (from error messages)
- Cloud: AWS (S3, CloudFront, ELB)
- Auth: OAuth 2.0 + JWT

### Quick Wins to Test First
1. Subdomain takeover on dev-old.target.com (CNAME dangling)
2. Open redirect on /oauth/callback
3. IDOR on /api/v2/users
4. S3 bucket target-uploads is publicly listable
```

---

## Automation vs Manual Balance

| Phase                  | Automated | Manual Review |
|------------------------|-----------|---------------|
| Subdomain enumeration  | 95%       | 5% (verify interesting finds) |
| HTTP probing           | 100%      | 0%            |
| Content discovery      | 80%       | 20% (interpret results) |
| JS analysis            | 60%       | 40% (read logic, find hidden endpoints) |
| Parameter discovery    | 70%       | 30% (context-aware guessing) |
| Vulnerability scanning | 50%       | 50% (validate, reduce false positives) |
| Cloud recon            | 80%       | 20% (interpret permissions) |
