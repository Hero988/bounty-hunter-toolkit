#!/usr/bin/env bash
# Recon Orchestrator - Passive + Active reconnaissance pipeline
# Usage: recon_orchestrator.sh <domain> <output_dir> <scope_json>
# All discovered hosts are filtered through scope_guard.py before further testing.

set -euo pipefail

DOMAIN="${1:?Usage: recon_orchestrator.sh <domain> <output_dir> <scope_json>}"
OUTPUT_DIR="${2:?Provide output directory}"
SCOPE_JSON="${3:?Provide scope.json path}"
TOOLKIT_DIR="${HOME}/.bounty-hunter-toolkit"
SCOPE_GUARD="${TOOLKIT_DIR}/scripts/scope_guard.py"
RATE_LIMIT="${RATE_LIMIT:-50}"
THREADS="${THREADS:-10}"

# Create output structure
mkdir -p "${OUTPUT_DIR}/recon/raw" "${OUTPUT_DIR}/recon/endpoints" "${OUTPUT_DIR}/recon/directories" "${OUTPUT_DIR}/logs"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "${OUTPUT_DIR}/logs/recon.log"; }

log "Starting recon for: ${DOMAIN}"
log "Output: ${OUTPUT_DIR}"
log "Rate limit: ${RATE_LIMIT} req/s, Threads: ${THREADS}"

# ============================================================
# PHASE 1: Passive Subdomain Enumeration
# ============================================================
log "=== Phase 1: Passive Subdomain Enumeration ==="

SUBS_RAW="${OUTPUT_DIR}/recon/raw/subdomains-raw.txt"
SUBS_FINAL="${OUTPUT_DIR}/recon/subdomains.txt"

# Subfinder
if command -v subfinder &>/dev/null; then
    log "Running subfinder..."
    subfinder -d "${DOMAIN}" -all -silent 2>/dev/null >> "${SUBS_RAW}" || true
    log "  subfinder found $(wc -l < "${SUBS_RAW}" 2>/dev/null || echo 0) subdomains"
fi

# Assetfinder
if command -v assetfinder &>/dev/null; then
    log "Running assetfinder..."
    assetfinder --subs-only "${DOMAIN}" 2>/dev/null >> "${SUBS_RAW}" || true
fi

# Certificate Transparency (crt.sh)
log "Querying crt.sh..."
curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null | \
    python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    seen = set()
    for entry in data:
        for name in entry.get('name_value', '').split('\n'):
            name = name.strip().lower()
            if name and '*' not in name and name not in seen:
                seen.add(name)
                print(name)
except: pass
" >> "${SUBS_RAW}" 2>/dev/null || true

# Deduplicate and sort
if [ -f "${SUBS_RAW}" ]; then
    sort -u "${SUBS_RAW}" | tr '[:upper:]' '[:lower:]' > "${SUBS_FINAL}"
    TOTAL_SUBS=$(wc -l < "${SUBS_FINAL}")
    log "Total unique subdomains: ${TOTAL_SUBS}"
else
    touch "${SUBS_FINAL}"
    log "No subdomains found"
fi

# ============================================================
# PHASE 2: Scope Filtering
# ============================================================
log "=== Phase 2: Scope Filtering ==="

SUBS_INSCOPE="${OUTPUT_DIR}/recon/subdomains-inscope.txt"
SUBS_OUTSCOPE="${OUTPUT_DIR}/recon/subdomains-outscope.txt"

while IFS= read -r sub; do
    result=$(python "${SCOPE_GUARD}" "${SCOPE_JSON}" "${sub}" 2>/dev/null || echo "FAIL")
    if echo "${result}" | grep -q "PASS"; then
        echo "${sub}" >> "${SUBS_INSCOPE}"
    else
        echo "${sub}" >> "${SUBS_OUTSCOPE}"
    fi
done < "${SUBS_FINAL}"

touch "${SUBS_INSCOPE}" "${SUBS_OUTSCOPE}"
INSCOPE_COUNT=$(wc -l < "${SUBS_INSCOPE}" 2>/dev/null || echo 0)
OUTSCOPE_COUNT=$(wc -l < "${SUBS_OUTSCOPE}" 2>/dev/null || echo 0)
log "In-scope: ${INSCOPE_COUNT}, Out-of-scope: ${OUTSCOPE_COUNT}"

# ============================================================
# PHASE 3: Historical URL Collection
# ============================================================
log "=== Phase 3: Historical URL Collection ==="

URLS_RAW="${OUTPUT_DIR}/recon/raw/urls-raw.txt"
URLS_FINAL="${OUTPUT_DIR}/recon/urls.txt"

# GAU (GetAllUrls)
if command -v gau &>/dev/null; then
    log "Running gau..."
    cat "${SUBS_INSCOPE}" | gau --threads "${THREADS}" 2>/dev/null >> "${URLS_RAW}" || true
fi

# Waybackurls
if command -v waybackurls &>/dev/null; then
    log "Running waybackurls..."
    cat "${SUBS_INSCOPE}" | waybackurls 2>/dev/null >> "${URLS_RAW}" || true
fi

# Deduplicate URLs
if [ -f "${URLS_RAW}" ]; then
    sort -u "${URLS_RAW}" > "${URLS_FINAL}"
    log "Total unique URLs: $(wc -l < "${URLS_FINAL}")"
else
    touch "${URLS_FINAL}"
fi

# ============================================================
# PHASE 4: HTTP Probing (Active)
# ============================================================
log "=== Phase 4: HTTP Probing ==="

LIVE_HOSTS="${OUTPUT_DIR}/recon/live-hosts.txt"
LIVE_JSON="${OUTPUT_DIR}/recon/live-hosts.json"

if command -v httpx &>/dev/null; then
    log "Running httpx..."
    cat "${SUBS_INSCOPE}" | httpx -silent \
        -status-code -title -tech-detect -follow-redirects \
        -threads "${THREADS}" \
        -rate-limit "${RATE_LIMIT}" \
        -json -o "${LIVE_JSON}" 2>/dev/null || true

    # Extract simple list
    if [ -f "${LIVE_JSON}" ]; then
        python -c "
import json, sys
seen = set()
for line in open('${LIVE_JSON}'):
    try:
        d = json.loads(line)
        url = d.get('url', '')
        if url and url not in seen:
            seen.add(url)
            print(url)
    except: pass
" > "${LIVE_HOSTS}" 2>/dev/null || true
        log "Live hosts: $(wc -l < "${LIVE_HOSTS}" 2>/dev/null || echo 0)"
    fi
else
    log "[WARN] httpx not installed, skipping HTTP probing"
    cp "${SUBS_INSCOPE}" "${LIVE_HOSTS}" 2>/dev/null || touch "${LIVE_HOSTS}"
fi

# ============================================================
# PHASE 5: Port Scanning
# ============================================================
log "=== Phase 5: Port Scanning ==="

if command -v nmap &>/dev/null; then
    # Only scan if we have a manageable number of hosts
    HOST_COUNT=$(wc -l < "${SUBS_INSCOPE}" 2>/dev/null || echo 0)
    if [ "${HOST_COUNT}" -gt 0 ] && [ "${HOST_COUNT}" -le 50 ]; then
        log "Running nmap on ${HOST_COUNT} hosts (top 1000 ports)..."
        nmap -sV -T3 --top-ports 1000 \
            -iL "${SUBS_INSCOPE}" \
            -oN "${OUTPUT_DIR}/recon/nmap-results.txt" \
            -oX "${OUTPUT_DIR}/recon/nmap-results.xml" \
            2>/dev/null || true
        log "Nmap scan complete"
    elif [ "${HOST_COUNT}" -gt 50 ]; then
        log "[INFO] Too many hosts (${HOST_COUNT}) for full nmap scan. Scanning first 20..."
        head -20 "${SUBS_INSCOPE}" > "${OUTPUT_DIR}/recon/raw/nmap-targets.txt"
        nmap -sV -T3 --top-ports 100 \
            -iL "${OUTPUT_DIR}/recon/raw/nmap-targets.txt" \
            -oN "${OUTPUT_DIR}/recon/nmap-results.txt" \
            2>/dev/null || true
    fi
else
    log "[WARN] nmap not installed, skipping port scan"
fi

# ============================================================
# PHASE 6: Technology Profiling
# ============================================================
log "=== Phase 6: Technology Profiling ==="

TECH_PROFILE="${OUTPUT_DIR}/recon/tech-profile.md"

if [ -f "${LIVE_JSON}" ]; then
    python -c "
import json, collections

tech_counter = collections.Counter()
host_techs = {}

for line in open('${LIVE_JSON}'):
    try:
        d = json.loads(line)
        url = d.get('url', '')
        techs = d.get('tech', [])
        title = d.get('title', '')
        status = d.get('status_code', 0)
        if techs:
            host_techs[url] = {'techs': techs, 'title': title, 'status': status}
            for t in techs:
                tech_counter[t] += 1
    except: pass

with open('${TECH_PROFILE}', 'w') as f:
    f.write('# Technology Profile\n\n')
    f.write('## Technology Summary\n\n')
    for tech, count in tech_counter.most_common(30):
        f.write(f'- **{tech}**: {count} host(s)\n')
    f.write(f'\n## Host Details\n\n')
    for url, info in sorted(host_techs.items()):
        f.write(f'### {url}\n')
        f.write(f'- Status: {info[\"status\"]}\n')
        f.write(f'- Title: {info[\"title\"]}\n')
        f.write(f'- Technologies: {\", \".join(info[\"techs\"])}\n\n')

print(f'Tech profile: {len(tech_counter)} unique technologies across {len(host_techs)} hosts')
" 2>/dev/null || true
    log "Tech profile generated: ${TECH_PROFILE}"
else
    echo "# Technology Profile\n\nNo httpx data available." > "${TECH_PROFILE}"
fi

# ============================================================
# Summary
# ============================================================
log ""
log "=== Recon Summary ==="
log "Subdomains found: $(wc -l < "${SUBS_FINAL}" 2>/dev/null || echo 0)"
log "In-scope subdomains: $(wc -l < "${SUBS_INSCOPE}" 2>/dev/null || echo 0)"
log "Historical URLs: $(wc -l < "${URLS_FINAL}" 2>/dev/null || echo 0)"
log "Live hosts: $(wc -l < "${LIVE_HOSTS}" 2>/dev/null || echo 0)"
log "Output directory: ${OUTPUT_DIR}/recon/"
log "=== Recon Complete ==="
