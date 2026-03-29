# Tools Reference

Quick reference for every tool used in the bug bounty hunting toolkit. Covers purpose, essential flags, common usage patterns, and pipe chains.

---

## Reconnaissance

### subfinder

**Purpose:** Passive subdomain enumeration from multiple sources (APIs, certificate transparency, etc.)

```bash
# Basic usage
subfinder -d target.com -o subs.txt

# Silent mode (clean output for piping)
subfinder -d target.com -silent

# Use all sources (configure API keys in ~/.config/subfinder/provider-config.yaml)
subfinder -d target.com -all -o subs.txt

# Multiple domains
subfinder -dL domains.txt -o subs.txt

# With specific sources
subfinder -d target.com -sources crtsh,virustotal,shodan

# Pipe to httpx for live hosts
subfinder -d target.com -silent | httpx -silent -o live.txt
```

**Key flags:** `-d` domain, `-dL` domain list, `-o` output, `-silent` clean output, `-all` use all sources, `-sources` specific sources, `-recursive` recursive enumeration

---

### assetfinder

**Purpose:** Fast subdomain discovery (simpler than subfinder, good for quick checks).

```bash
# Basic usage
assetfinder target.com

# Subdomains only (no related domains)
assetfinder --subs-only target.com

# Pipe to sorting
assetfinder --subs-only target.com | sort -u > subs.txt
```

**Key flags:** `--subs-only` subdomains only

---

### dnsx

**Purpose:** DNS toolkit -- resolve, query records, wildcard filtering.

```bash
# Resolve subdomains
cat subs.txt | dnsx -silent -a -resp

# Get CNAME records (useful for subdomain takeover)
cat subs.txt | dnsx -silent -cname -resp

# Filter out wildcard DNS
cat subs.txt | dnsx -silent -wd target.com

# Multiple record types
cat subs.txt | dnsx -silent -a -aaaa -cname -mx -txt -resp

# Reverse DNS
echo 1.2.3.4 | dnsx -silent -ptr -resp
```

**Key flags:** `-a` A records, `-aaaa` AAAA, `-cname` CNAME, `-mx` MX, `-txt` TXT, `-ptr` PTR, `-resp` show response, `-wd` wildcard domain filter, `-silent` clean output

---

### naabu

**Purpose:** Fast port scanner. SYN/CONNECT scan across targets.

```bash
# Scan common ports
naabu -host target.com -o ports.txt

# Top 1000 ports
naabu -host target.com -top-ports 1000

# Specific ports
naabu -host target.com -p 80,443,8080,8443

# Full port scan
naabu -host target.com -p -

# Scan from host list and pipe to httpx
naabu -list hosts.txt -top-ports 100 -silent | httpx -silent

# With rate limiting
naabu -host target.com -rate 500 -p - -silent
```

**Key flags:** `-host` target, `-list` host list file, `-p` ports (use `-` for all), `-top-ports` N, `-rate` packets/sec, `-silent` clean output, `-o` output file

**Windows note:** Naabu requires Npcap or WinPcap on Windows for SYN scanning. Use `-scan-type c` for CONNECT scan if SYN scan fails.

---

### nmap

**Purpose:** Comprehensive port scanning and service detection.

```bash
# Quick scan top 1000 ports
nmap -sV target.com

# Service version + OS detection
nmap -sV -O target.com

# Aggressive scan with scripts
nmap -A target.com

# Specific ports
nmap -p 80,443,8080 target.com

# All ports
nmap -p- target.com

# UDP scan (slow, requires root/admin)
nmap -sU --top-ports 100 target.com

# Script scan for vulns
nmap --script vuln target.com

# HTTP enumeration
nmap -p 80,443 --script http-enum target.com

# Output all formats
nmap -sV target.com -oA scan_results
```

**Key flags:** `-sV` version detection, `-sC` default scripts, `-O` OS detection, `-A` aggressive, `-p` ports, `-p-` all ports, `--script` NSE scripts, `-oA` output all formats, `-sU` UDP scan, `-Pn` skip host discovery

**Windows note:** SYN scan (`-sS`) requires administrator privileges. Use `-sT` (TCP connect) if running unprivileged.

---

## Web Probing & Crawling

### httpx

**Purpose:** HTTP probe -- check live hosts, grab titles, status codes, tech stack.

```bash
# Probe live hosts
cat subs.txt | httpx -silent -o live.txt

# With status codes and titles
cat subs.txt | httpx -silent -status-code -title -content-length

# Technology detection
cat subs.txt | httpx -silent -tech-detect

# Follow redirects
cat subs.txt | httpx -silent -follow-redirects -status-code

# Filter by status code
cat subs.txt | httpx -silent -mc 200,301,302,403

# Full output
cat subs.txt | httpx -status-code -title -tech-detect -content-length -follow-redirects -o httpx_results.txt

# With custom ports
cat subs.txt | httpx -silent -ports 80,443,8080,8443

# JSON output for parsing
cat subs.txt | httpx -silent -json -o results.json

# Screenshot (requires Chrome/Chromium)
cat subs.txt | httpx -silent -screenshot -screenshot-timeout 10
```

**Key flags:** `-silent` clean output, `-status-code` (`-sc`), `-title`, `-tech-detect`, `-content-length` (`-cl`), `-follow-redirects` (`-fr`), `-mc` match codes, `-fc` filter codes, `-ports`, `-json`, `-screenshot`, `-o` output, `-threads` concurrency

---

### katana

**Purpose:** Web crawler -- spider sites for URLs, endpoints, JS files.

```bash
# Crawl a single target
katana -u https://target.com -o urls.txt

# Crawl with depth
katana -u https://target.com -d 5

# Crawl from URL list
katana -list live.txt -o all_urls.txt

# JavaScript parsing (extract endpoints from JS files)
katana -u https://target.com -js-crawl

# Filter by extension
katana -u https://target.com -ef css,png,jpg,gif,svg,woff,ttf

# With headless browser (for SPAs)
katana -u https://target.com -headless

# Scope control
katana -u https://target.com -fs dn  # filter scope: display name (same domain)

# Output only unique paths
katana -u https://target.com -silent | sort -u > paths.txt
```

**Key flags:** `-u` URL, `-list` URL list, `-d` depth, `-js-crawl` parse JS, `-headless` browser mode, `-ef` extension filter, `-fs` filter scope, `-silent`, `-o` output

---

### gau (GetAllUrls)

**Purpose:** Fetch known URLs from Wayback Machine, Common Crawl, OTX, URLScan.

```bash
# Get all known URLs for domain
gau target.com

# With specific providers
gau --providers wayback,commoncrawl,otx target.com

# Filter by extension
gau target.com | grep -E '\.(js|php|aspx|jsp)$'

# From subdomain list
cat subs.txt | gau --threads 5

# Only fetch from date range
gau --from 202401 --to 202501 target.com

# Find parameters
gau target.com | grep '=' | sort -u > params.txt
```

**Key flags:** `--providers` source list, `--threads` concurrency, `--from`/`--to` date filter, `--blacklist` extension blacklist, `--o` output

---

### waybackurls

**Purpose:** Fetch URLs from Wayback Machine specifically.

```bash
# Basic usage
echo target.com | waybackurls

# Pipe from subdomains
cat subs.txt | waybackurls | sort -u > wayback.txt

# Find interesting files
echo target.com | waybackurls | grep -E '\.(json|xml|config|env|bak|sql|zip)$'

# Find parameters for fuzzing
echo target.com | waybackurls | grep '?' | sort -u > params.txt
```

---

## Vulnerability Scanning

### nuclei

**Purpose:** Template-based vulnerability scanner. Massive template library for known CVEs, misconfigs, exposures.

```bash
# Scan with all templates
nuclei -u https://target.com

# Scan from URL list
nuclei -l live.txt -o nuclei_results.txt

# Specific severity
nuclei -l live.txt -severity critical,high

# Specific tags
nuclei -l live.txt -tags cve,rce,sqli,xss,ssrf

# Specific templates
nuclei -l live.txt -t nuclei-templates/cves/

# Update templates
nuclei -update-templates

# With rate limiting
nuclei -l live.txt -rate-limit 100 -concurrency 25

# Headless templates (browser-based)
nuclei -l live.txt -headless

# JSON output
nuclei -l live.txt -json -o results.json

# Exclude certain templates
nuclei -l live.txt -exclude-tags dos,fuzz

# Report to interact.sh
nuclei -l live.txt -interactsh-server https://your-server.interact.sh
```

**Key flags:** `-u` URL, `-l` URL list, `-t` template path, `-tags`, `-severity`, `-rate-limit`, `-concurrency`, `-json`, `-o` output, `-update-templates`, `-exclude-tags`, `-headless`

---

### dalfox

**Purpose:** Dedicated XSS scanner with smart payload generation, WAF detection, and parameter analysis.

```bash
# Scan a URL
dalfox url "https://target.com/search?q=test"

# From URL list with parameters
dalfox file urls_with_params.txt

# Pipe from gau
gau target.com | grep '=' | dalfox pipe

# With custom payload
dalfox url "https://target.com/search?q=test" -p "custom_payload"

# Blind XSS with callback
dalfox url "https://target.com/search?q=test" --blind https://your-xss-hunter.com

# Mining mode (DOM analysis)
dalfox url "https://target.com" --mining-dom

# With custom headers
dalfox url "https://target.com/search?q=test" -H "Cookie: session=abc"

# Output
dalfox url "https://target.com/search?q=test" -o results.txt
```

**Key flags:** `url`/`file`/`pipe` mode, `-p` custom payload, `--blind` callback URL, `--mining-dom` DOM analysis, `-H` header, `-o` output, `--waf-evasion`, `--skip-bav` skip basic param verification

---

## Fuzzing

### ffuf

**Purpose:** Fast web fuzzer -- directory/file discovery, parameter fuzzing, virtual host discovery.

```bash
# Directory brute-force
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt

# With extensions
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.html,.js,.txt,.bak

# Filter by status code
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403

# Filter out specific size (remove noise)
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 4242

# Filter by lines or words
ffuf -u https://target.com/FUZZ -w wordlist.txt -fl 10 -fw 20

# POST parameter fuzzing
ffuf -u https://target.com/login -w wordlist.txt -X POST -d "user=admin&pass=FUZZ"

# Header fuzzing / virtual host discovery
ffuf -u https://target.com -w subs.txt -H "Host: FUZZ.target.com" -fs 4242

# Multiple FUZZ keywords
ffuf -u https://target.com/FUZZ1/FUZZ2 -w dirs.txt:FUZZ1 -w files.txt:FUZZ2

# API endpoint discovery
ffuf -u https://target.com/api/FUZZ -w api-wordlist.txt -mc 200,401,403

# With authentication
ffuf -u https://target.com/FUZZ -w wordlist.txt -H "Authorization: Bearer TOKEN"

# Rate limiting
ffuf -u https://target.com/FUZZ -w wordlist.txt -rate 50

# Recursive
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Output
ffuf -u https://target.com/FUZZ -w wordlist.txt -o results.json -of json
```

**Key flags:** `-u` URL, `-w` wordlist, `-e` extensions, `-mc` match codes, `-fc` filter codes, `-fs` filter size, `-fl` filter lines, `-fw` filter words, `-X` method, `-d` data, `-H` header, `-rate` req/sec, `-recursion`, `-o` output, `-of` output format

**Windows/Git Bash note:** Wordlist paths use forward slashes. If using SecLists installed via Git, typical path: `/c/Tools/SecLists/Discovery/Web-Content/common.txt`

---

## Subdomain Takeover

### subjack

**Purpose:** Detect subdomain takeover vulnerabilities by checking CNAME records against known vulnerable services.

```bash
# Basic check
subjack -w subs.txt -t 100 -timeout 30 -ssl -o takeovers.txt

# With custom fingerprints
subjack -w subs.txt -t 100 -a  # -a checks all records, not just CNAME

# Verbose
subjack -w subs.txt -t 100 -v
```

**Key flags:** `-w` wordlist (subdomain list), `-t` threads, `-timeout` seconds, `-ssl` check HTTPS, `-a` check all, `-o` output, `-v` verbose

---

## Interaction / Out-of-Band

### interactsh-client

**Purpose:** Out-of-band interaction detection. Get a unique domain that logs all DNS/HTTP/SMTP interactions.

```bash
# Start client (generates unique subdomain)
interactsh-client

# With specific server
interactsh-client -server interact.sh

# JSON output
interactsh-client -json

# With token for persistence
interactsh-client -token YOUR_TOKEN

# Poll interval
interactsh-client -poll-interval 5
```

**Usage pattern:** Start client, get the unique URL (e.g., `abc123.interact.sh`), inject it into SSRF/XXE/blind-XSS payloads, watch for callbacks.

**Key flags:** `-server`, `-json`, `-token`, `-poll-interval`, `-output`

---

## HTTP Client

### curl

**Purpose:** Swiss-army knife for HTTP requests. Essential for manual testing and PoC verification.

```bash
# Basic GET
curl -s https://target.com

# With response headers
curl -sI https://target.com
curl -sv https://target.com 2>&1

# POST with data
curl -s -X POST https://target.com/login -d "user=admin&pass=test"

# POST JSON
curl -s -X POST https://target.com/api -H "Content-Type: application/json" -d '{"key":"value"}'

# With cookies
curl -s https://target.com -b "session=abc123"

# Follow redirects
curl -sL https://target.com

# Custom headers
curl -s https://target.com -H "Authorization: Bearer TOKEN" -H "X-Custom: value"

# Save response
curl -s https://target.com -o response.html

# With proxy (Burp Suite)
curl -s https://target.com -x http://127.0.0.1:8080 -k

# PUT request
curl -s -X PUT https://target.com/api/resource -H "Content-Type: application/json" -d '{"key":"newvalue"}'

# Upload file
curl -s -X POST https://target.com/upload -F "file=@shell.php"

# Show timing info
curl -s -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s | Size: %{size_download}\n" https://target.com

# SSRF testing
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
```

**Key flags:** `-s` silent, `-v` verbose, `-I` HEAD only, `-L` follow redirects, `-X` method, `-d` data, `-H` header, `-b` cookie, `-o` output, `-x` proxy, `-k` skip TLS verify, `-F` form upload, `-w` write-out format

**Windows/Git Bash note:** Use single quotes for JSON data. If single quotes cause issues in Git Bash, escape double quotes: `-d "{\"key\":\"value\"}"`. Alternatively, use a file: `-d @data.json`.

---

## Common Pipe Chains

### Full Recon Pipeline

```bash
# Subdomain enum -> probe -> crawl -> scan
subfinder -d target.com -silent | httpx -silent -o live.txt
cat live.txt | katana -silent -d 3 -js-crawl | sort -u > urls.txt
cat live.txt | nuclei -severity critical,high -o vulns.txt
```

### Parameter Discovery Pipeline

```bash
# Find URLs with parameters from multiple sources
(gau target.com; echo target.com | waybackurls; katana -u https://target.com -silent) | sort -u | grep '=' > params.txt
```

### XSS Pipeline

```bash
# Collect parameterized URLs and fuzz for XSS
gau target.com | grep '=' | sort -u | dalfox pipe --blind https://your-xss-hunter.com
```

### Subdomain Takeover Pipeline

```bash
subfinder -d target.com -silent | dnsx -silent -cname -resp | tee cnames.txt
subfinder -d target.com -silent > subs.txt && subjack -w subs.txt -ssl -t 100
```

### Port Discovery Pipeline

```bash
# Find subdomains -> scan ports -> probe HTTP
subfinder -d target.com -silent > subs.txt
naabu -list subs.txt -top-ports 100 -silent | httpx -silent -o live_with_ports.txt
```

### Quick Nuclei Scan on Specific Vuln Class

```bash
nuclei -l live.txt -tags sqli -severity critical,high -o sqli_findings.txt
nuclei -l live.txt -tags ssrf -o ssrf_findings.txt
nuclei -l live.txt -tags xss -o xss_findings.txt
```

### JavaScript File Analysis

```bash
# Collect JS files and search for secrets
katana -u https://target.com -silent -js-crawl | grep '\.js$' | sort -u > js_files.txt
nuclei -l js_files.txt -tags exposure,token -o js_secrets.txt
```

---

## Platform-Specific Notes (Windows / Git Bash)

### General

- Use forward slashes in paths (`/c/Tools/` not `C:\Tools\`)
- Git Bash may not support all pipe operations -- fall back to PowerShell if needed
- Some tools need Windows Defender exclusions to run without interference
- Install Go-based tools with `go install github.com/tool/name@latest`

### Tool Installation

Most Go-based tools (subfinder, httpx, nuclei, ffuf, katana, etc.):

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/haccer/subjack@latest
go install -v github.com/hahwul/dalfox/v2@latest
```

Binaries go to `$GOPATH/bin` (typically `~/go/bin`). Ensure this is in your `$PATH`.

### Common Gotchas

- **naabu**: Needs Npcap for SYN scan on Windows. Use `-scan-type c` for CONNECT scan as fallback.
- **nmap**: Needs to be installed separately (not Go-based). Install from https://nmap.org. Run as Administrator for SYN scans.
- **nuclei templates**: Auto-download on first run. Templates stored in `~/.local/nuclei-templates/` (or `$HOME/nuclei-templates` on Windows).
- **interactsh**: Firewall may block callbacks. Ensure outbound DNS is allowed.
- **ffuf**: When piping wordlists on Windows, watch for CRLF line endings. Convert with `dos2unix` or use `-ic` (ignore comments/empty) flag.
- **curl**: Git Bash ships its own curl. Verify with `which curl`. Windows system curl may behave differently.
