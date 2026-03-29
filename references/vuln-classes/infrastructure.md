# Infrastructure Vulnerabilities Reference

## Covers: Subdomain Takeover, Cloud Misconfig (AWS/Azure/GCP), Exposed Services, Default Credentials

---

## 1. Testing Checklist

### Subdomain Takeover
1. Enumerate all subdomains: DNS brute force, certificate transparency, passive DNS
2. Check for CNAME records pointing to external services (S3, GitHub Pages, Heroku, Azure, etc.)
3. Test if the CNAME target is claimable (404/NXDOMAIN on the external service)
4. Verify fingerprints: unique error messages indicating unclaimed resource
5. Check for dangling NS records (delegate to a zone you can register)
6. Check for A records pointing to deprovisioned cloud IPs
7. Test if the subdomain is on a wildcard cert (increases impact)
8. Verify the takeover is possible by actually claiming the resource (where program allows)

### Cloud Misconfiguration - AWS
1. Test S3 buckets for public access: listing, reading, writing
2. Check for public EBS snapshots and AMIs
3. Test for overly permissive IAM policies (if you have credentials)
4. Check for public RDS/Elasticsearch instances
5. Test Lambda function URLs for auth bypass
6. Check for CloudFront distributions serving private S3 data
7. Test API Gateway endpoints for missing authentication
8. Check for SQS/SNS with public access policies
9. Test for EC2 metadata SSRF (covered in server-side.md)

### Cloud Misconfiguration - Azure
1. Test Azure Blob Storage containers for public access
2. Check for exposed Azure Functions endpoints
3. Test Azure AD app registrations for overly permissive scopes
4. Check for Key Vault access policies
5. Test Cosmos DB endpoints for open access
6. Check for public Azure DevOps repositories

### Cloud Misconfiguration - GCP
1. Test GCS buckets for public access
2. Check for public BigQuery datasets
3. Test Cloud Functions for unauthenticated access
4. Check for Firestore/Datastore public rules
5. Test for overly permissive service account keys
6. Check for public GCE disk snapshots

### Exposed Services
1. Port scan target IP ranges for common service ports
2. Identify services with version detection
3. Check for unprotected admin interfaces: Jenkins, Kibana, Grafana, phpMyAdmin
4. Test for exposed databases: MongoDB, Elasticsearch, Redis, Memcached
5. Check for exposed CI/CD: Jenkins, GitLab CI, Drone
6. Test for exposed monitoring: Prometheus, Grafana, Nagios
7. Check for exposed message queues: RabbitMQ, Kafka management
8. Verify services are not honeypots

### Default Credentials
1. Identify all login interfaces on discovered services
2. Test common default credentials for identified service/product
3. Check for default API keys or tokens
4. Test demo/test accounts: demo/demo, test/test, guest/guest
5. Check documentation for default installation credentials
6. Test for blank passwords on admin accounts
7. Check for hardcoded credentials in public documentation

---

## 2. Tool Commands

### Subdomain Enumeration
```bash
# subfinder - passive enumeration
subfinder -d target.com -all -o subdomains.txt

# amass - comprehensive enumeration
amass enum -d target.com -active -o amass-subs.txt

# puredns - DNS brute force with massdns resolver
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt target.com -r resolvers.txt -w brute-subs.txt

# Combine and deduplicate
cat subdomains.txt amass-subs.txt brute-subs.txt | sort -u > all-subs.txt

# Certificate transparency
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u >> all-subs.txt
```

### Subdomain Takeover
```bash
# subjack - automated takeover detection
subjack -w all-subs.txt -t 100 -timeout 30 -o takeover-results.txt -ssl

# nuclei with takeover templates
nuclei -l all-subs.txt -t takeovers/ -o nuclei-takeover.txt

# Check CNAME records manually
while read sub; do
  cname=$(dig +short CNAME "$sub" | head -1)
  if [ -n "$cname" ]; then
    echo "$sub -> $cname"
  fi
done < all-subs.txt | tee cnames.txt

# can-i-take-over-xyz - check fingerprints
# Reference: https://github.com/EdOverflow/can-i-take-over-xyz

# Check for dangling A records (cloud IPs not in target's control)
while read sub; do
  ip=$(dig +short A "$sub" | head -1)
  if [ -n "$ip" ]; then
    echo "$sub -> $ip"
  fi
done < all-subs.txt > a-records.txt
```

### AWS
```bash
# S3 bucket enumeration and testing
aws s3 ls s3://target-bucket --no-sign-request
aws s3 ls s3://target-bucket --no-sign-request --recursive
aws s3 cp s3://target-bucket/secret.txt /tmp/ --no-sign-request

# S3 bucket write test (only if program allows)
echo "security_test" > /tmp/test.txt
aws s3 cp /tmp/test.txt s3://target-bucket/security_test.txt --no-sign-request

# Check bucket ACL
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request

# Public EBS snapshot search
aws ec2 describe-snapshots --owner-ids ACCOUNT_ID --region us-east-1 --query 'Snapshots[?StartTime>=`2024-01-01`]'

# Public AMI search
aws ec2 describe-images --owners ACCOUNT_ID --region us-east-1

# S3 bucket name discovery
# Common patterns: target.com, target-prod, target-staging, target-backup, target-dev
# Use cloud_enum or s3scanner
cloud_enum -k target -l cloud_results.txt

# ScoutSuite - full AWS audit (if you have credentials)
scout suite aws --no-browser
```

### Azure
```bash
# Azure blob storage test
curl -s "https://targetaccount.blob.core.windows.net/\$logs?restype=container&comp=list"
curl -s "https://targetaccount.blob.core.windows.net/public?restype=container&comp=list"

# MicroBurst - Azure enumeration
Invoke-EnumerateAzureBlobs -Base target
Invoke-EnumerateAzureSubDomains -Base target

# Azure AD enumeration
# AADInternals, ROADtools
```

### GCP
```bash
# GCS bucket test
curl -s "https://storage.googleapis.com/target-bucket/"
gsutil ls gs://target-bucket/
gsutil cp gs://target-bucket/secret.txt /tmp/

# GCP enumeration
gcp_enum -k target
```

### Port Scanning & Service Discovery
```bash
# nmap - service version detection on common ports
nmap -sV -sC -T4 -p 21,22,23,25,53,80,110,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017 target.com -oA nmap-scan

# masscan - fast full port scan
masscan -p1-65535 TARGET_IP --rate=1000 -oL masscan-results.txt

# httpx - identify HTTP services on all subdomains
httpx -l all-subs.txt -ports 80,443,8080,8443,3000,5000,8000,9090 -title -status-code -tech-detect -o httpx-results.txt

# nuclei - scan for known vulns and misconfigs
nuclei -l all-subs.txt -t exposed-panels/ -t technologies/ -t misconfiguration/ -o nuclei-results.txt
```

### Default Credentials
```bash
# nuclei with default login templates
nuclei -l httpx-results.txt -t default-logins/ -o default-creds-results.txt

# changeme - default credential scanner
changeme TARGET_IP

# Common default credential pairs (test manually):
# admin:admin, admin:password, admin:123456, root:root, root:toor
# test:test, demo:demo, guest:guest, user:user
# Service-specific: Jenkins (no auth), MongoDB (no auth), Redis (no auth)
# Elasticsearch (no auth), Kibana (no auth), Grafana (admin:admin)
```

---

## 3. Payloads

### Subdomain Takeover Fingerprints
```
# GitHub Pages
"There isn't a GitHub Pages site here."

# Heroku
"No such app"
"herokucdn.com/error-pages/no-such-app.html"

# AWS S3
"NoSuchBucket"
"The specified bucket does not exist"

# Azure (various)
"404 Web Site not found"  (*.azurewebsites.net)
"Invalid Host Name"

# Shopify
"Sorry, this shop is currently unavailable"

# Fastly
"Fastly error: unknown domain"

# Ghost
"The thing you were looking for is no longer here"

# Pantheon
"404 error unknown site"

# Tumblr
"Whatever you were looking for doesn't currently exist at this address"

# WordPress.com
"Do you want to register"

# Surge.sh
"project not found"

# Fly.io
"404 Not Found" with fly.io headers

# Netlify
"Not Found - Request ID:"
```

### S3 Bucket Name Patterns
```
target.com
target-com
target
target-prod
target-production
target-staging
target-stage
target-dev
target-development
target-test
target-qa
target-backup
target-backups
target-assets
target-media
target-uploads
target-static
target-logs
target-data
target-archive
target-internal
target-private
target-public
```

### Default Credentials Database
```
# Jenkins
(no authentication by default on older versions)
admin:admin
admin:jenkins

# Grafana
admin:admin

# Kibana / Elasticsearch
(no auth by default)
elastic:changeme

# MongoDB
(no auth by default)

# Redis
(no auth by default, check with: redis-cli -h TARGET ping)

# RabbitMQ
guest:guest

# Tomcat Manager
tomcat:tomcat
admin:admin
tomcat:s3cret

# phpMyAdmin
root:(empty)
root:root

# pgAdmin
pgadmin@pgadmin.org:admin

# Portainer
admin:admin (first-run setup)

# HashiCorp Consul
(no auth by default - ACL disabled)

# Kubernetes Dashboard
(check for skip-login option or default token)

# Docker Registry
(no auth by default on port 5000)
GET /v2/_catalog

# Prometheus
(no auth by default)

# Jupyter Notebook
(token in logs or empty password)

# Apache Airflow
airflow:airflow

# Solr
(no auth by default)
```

---

## 4. Bypass Techniques

### Subdomain Takeover Edge Cases
- **Dangling NS delegation**: If NS records point to a nameserver you can claim, you control all DNS for that subdomain
- **Expired domain CNAME**: CNAME points to domain that expired and can be re-registered
- **Race condition on deprovisioning**: Service deprovisions but DNS update is delayed
- **Wildcard subdomain**: Takeover `*.staging.target.com` by claiming the wildcard

### Cloud Access Bypass
- **S3 bucket policy vs ACL**: Bucket policy may deny but ACL allows (or vice versa)
- **Presigned URL exposure**: Search for leaked presigned S3 URLs (valid for hours/days)
- **Cross-account access**: Test if bucket allows access from any AWS account (Principal: *)
- **Region-specific endpoints**: Try different region endpoints for the same bucket
- **Azure SAS token exposure**: Search for leaked Shared Access Signature URLs
- **GCP signed URL exposure**: Search for leaked signed URLs

### Exposed Service Access
- **IP-based restriction bypass**: `X-Forwarded-For: 127.0.0.1`, `X-Real-IP: 10.0.0.1`
- **VPN/proxy bypass**: Access from cloud provider IPs that may be allowlisted
- **Path-based bypass**: `/admin` blocked but `/admin/` or `/Admin` or `/admin;.html` works
- **Port-based bypass**: Same service on non-standard port may lack access controls

---

## 5. Impact Escalation

### Subdomain Takeover
- Serve phishing pages on trusted domain
- Steal cookies scoped to parent domain (if `Domain=.target.com`)
- Bypass CSP if subdomain is in `script-src`
- Intercept OAuth flows using the subdomain
- Send emails from the subdomain (if MX records are also controllable)

### Cloud Misconfiguration
- **S3 read**: Exfiltrate all data (PII, backups, source code, credentials)
- **S3 write**: Replace static assets (JS files) for supply chain attack, deface website
- **IAM credentials**: Escalate to full AWS account access
- **EBS snapshots**: Mount and extract all data including encryption keys
- **Public RDS**: Full database access including all user data

### Exposed Services
- **Jenkins**: Access build logs (credentials), execute builds (RCE)
- **Elasticsearch/Kibana**: Full data access, query all indices
- **Redis**: Data access, potential RCE via Lua scripting or module loading
- **MongoDB**: Full database access without authentication
- **Docker Registry**: Pull images, extract secrets/source code
- **Kubernetes Dashboard**: Full cluster access, deploy containers

---

## 6. Chain Opportunities

| Found This | Look For |
|---|---|
| Subdomain takeover | Cookie theft (parent domain scope), CSP bypass, OAuth hijack |
| S3 bucket read | Credentials in files -> AWS escalation, source code -> more vulns |
| S3 bucket write | Replace JS assets -> stored XSS on main site, supply chain attack |
| Exposed Jenkins | Build logs for credentials, run builds for RCE, access SCM |
| Exposed Elasticsearch | Search for credentials, tokens, PII, internal URLs |
| Default creds on admin panel | Explore admin features for RCE, data access, config changes |
| Cloud IAM credentials | Full cloud account enumeration and escalation (Pacu, ScoutSuite) |
| Exposed Redis | SSRF -> Redis for RCE, data theft, session manipulation |
| Exposed Docker Registry | Pull images -> extract hardcoded secrets -> further access |

---

## 7. Common False Positives

- **Subdomain takeover**: CNAME exists but external service is properly configured (not claimable)
- **Subdomain takeover**: Getting a generic 404 that's the actual intended behavior, not a dangling record
- **S3 bucket listing**: Bucket is intentionally public (e.g., public datasets, open-source assets). Check if the data is actually sensitive
- **Exposed service**: Honeypot designed to look like an exposed service
- **Exposed service**: Service is intentionally public (e.g., public Grafana dashboard with no sensitive data)
- **Default credentials**: Login page exists but default creds don't work (test, don't assume)
- **Open port**: Port is open but the service requires authentication that you can't bypass
- **Cloud misconfiguration**: Resource is in a different account than the target's (verify ownership)

---

## 8. Report Snippets

### Subdomain Takeover
> The subdomain `[subdomain]` has a CNAME record pointing to `[external service]`, which is no longer claimed by the target organization. I was able to register this resource on `[service]` and serve arbitrary content on `[subdomain]`. Since cookies may be scoped to `*.target.com` and the subdomain may be trusted by CSP policies, this can be leveraged for session hijacking, phishing, and cross-site scripting against the main application.

### S3 Bucket Exposure
> The S3 bucket `[bucket-name]` allows [public listing/read/write] access without authentication. The bucket contains [number] objects including [description of sensitive data: database backups / user uploads / source code / credentials]. [If writable:] Additionally, the bucket allows unauthenticated writes, enabling an attacker to modify hosted assets such as JavaScript files served to users, leading to a supply chain attack affecting all visitors.

### Exposed Service
> An unauthenticated `[service name]` instance is accessible at `[URL/IP:port]`. This instance contains [sensitive data description / provides administrative access to...]. Using default credentials `[if applicable]`, I was able to access [specific functionality], which provides [specific impact: RCE via build execution / full database read access / internal network visibility].

### Default Credentials
> The `[service]` at `[URL]` is accessible with the default credentials `[username:password]`. This provides [admin/user] access to the application, allowing [specific capabilities: user management, data access, configuration changes, code execution]. This should be remediated by changing the default credentials and restricting network access to authorized users.
