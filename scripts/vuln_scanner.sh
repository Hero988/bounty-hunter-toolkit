#!/usr/bin/env bash
# Vulnerability Scanner - Tech-aware nuclei scanning + custom checks
# Usage: vuln_scanner.sh <live_hosts_file> <output_dir> <scope_json> [tech_profile]
# Key feature: Selects nuclei templates based on detected tech stack to reduce noise 80%+

set -euo pipefail

LIVE_HOSTS="${1:?Usage: vuln_scanner.sh <live_hosts_file> <output_dir> <scope_json> [tech_profile]}"
OUTPUT_DIR="${2:?Provide output directory}"
SCOPE_JSON="${3:?Provide scope.json path}"
TECH_PROFILE="${4:-${OUTPUT_DIR}/recon/tech-profile.md}"
TOOLKIT_DIR="${HOME}/.bounty-hunter-toolkit"
RATE_LIMIT="${RATE_LIMIT:-50}"
THREADS="${THREADS:-10}"

mkdir -p "${OUTPUT_DIR}/findings/nuclei" "${OUTPUT_DIR}/findings/custom" "${OUTPUT_DIR}/logs"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "${OUTPUT_DIR}/logs/vuln-scanner.log"; }

log "Starting vulnerability scanning"
log "Hosts: ${LIVE_HOSTS}"
log "Rate limit: ${RATE_LIMIT}, Threads: ${THREADS}"

# ============================================================
# PHASE 1: Detect Technologies for Smart Template Selection
# ============================================================
log "=== Phase 1: Technology Detection ==="

TECH_TAGS=""
if [ -f "${TECH_PROFILE}" ]; then
    # Extract technology names and map to nuclei tags
    TECH_TAGS=$(python -c "
import sys
tech_to_tags = {
    'wordpress': 'wordpress,wp',
    'drupal': 'drupal',
    'joomla': 'joomla',
    'nginx': 'nginx',
    'apache': 'apache',
    'iis': 'iis',
    'tomcat': 'tomcat',
    'php': 'php',
    'asp.net': 'asp',
    'node.js': 'nodejs',
    'express': 'nodejs',
    'react': 'react',
    'angular': 'angular',
    'vue': 'vue',
    'django': 'django,python',
    'flask': 'flask,python',
    'spring': 'spring,java',
    'laravel': 'laravel,php',
    'ruby on rails': 'rails,ruby',
    'jenkins': 'jenkins',
    'gitlab': 'gitlab',
    'grafana': 'grafana',
    'elasticsearch': 'elastic',
    'mongodb': 'mongodb',
    'mysql': 'mysql',
    'postgresql': 'postgres',
    'redis': 'redis',
    'docker': 'docker',
    'kubernetes': 'kubernetes',
    'aws': 'aws',
    'azure': 'azure',
    'graphql': 'graphql',
    'swagger': 'swagger',
    'cloudflare': 'cloudflare',
}
tags = set()
with open('${TECH_PROFILE}', errors='ignore') as f:
    content = f.read().lower()
for tech, tag_str in tech_to_tags.items():
    if tech in content:
        tags.update(tag_str.split(','))
if tags:
    print(','.join(sorted(tags)))
else:
    print('')
" 2>/dev/null || echo "")
    if [ -n "${TECH_TAGS}" ]; then
        log "Detected tech tags: ${TECH_TAGS}"
    else
        log "No specific technologies detected, using general scan"
    fi
else
    log "No tech profile available, using general scan"
fi

# ============================================================
# PHASE 2: Nuclei Scanning (Layered Approach)
# ============================================================

if ! command -v nuclei &>/dev/null; then
    log "[FAIL] nuclei not installed. Run setup.py first."
    exit 1
fi

# Layer 1: Exposures and Misconfigurations
log "=== Phase 2a: Exposure/Misconfiguration Scan ==="
nuclei -l "${LIVE_HOSTS}" \
    -t exposures/ -t misconfiguration/ -t miscellaneous/ \
    -severity medium,high,critical \
    -rate-limit "${RATE_LIMIT}" \
    -concurrency "${THREADS}" \
    -json -o "${OUTPUT_DIR}/findings/nuclei/layer1-exposures.json" \
    -silent 2>/dev/null || true
L1_COUNT=$(wc -l < "${OUTPUT_DIR}/findings/nuclei/layer1-exposures.json" 2>/dev/null || echo 0)
log "Layer 1 findings: ${L1_COUNT}"

# Layer 2: CVE checks (tech-aware if possible)
log "=== Phase 2b: CVE Scan ==="
if [ -n "${TECH_TAGS}" ]; then
    # Tech-aware: only run templates matching detected stack
    nuclei -l "${LIVE_HOSTS}" \
        -t cves/ \
        -tags "${TECH_TAGS}" \
        -severity medium,high,critical \
        -rate-limit "${RATE_LIMIT}" \
        -concurrency "${THREADS}" \
        -json -o "${OUTPUT_DIR}/findings/nuclei/layer2-cves-targeted.json" \
        -silent 2>/dev/null || true
    L2_COUNT=$(wc -l < "${OUTPUT_DIR}/findings/nuclei/layer2-cves-targeted.json" 2>/dev/null || echo 0)
    log "Layer 2 findings (targeted): ${L2_COUNT}"
else
    # Generic: top CVEs only
    nuclei -l "${LIVE_HOSTS}" \
        -t cves/ \
        -severity high,critical \
        -rate-limit "${RATE_LIMIT}" \
        -concurrency "${THREADS}" \
        -json -o "${OUTPUT_DIR}/findings/nuclei/layer2-cves-generic.json" \
        -silent 2>/dev/null || true
    L2_COUNT=$(wc -l < "${OUTPUT_DIR}/findings/nuclei/layer2-cves-generic.json" 2>/dev/null || echo 0)
    log "Layer 2 findings (generic): ${L2_COUNT}"
fi

# Layer 3: Vulnerability checks
log "=== Phase 2c: Vulnerability Scan ==="
nuclei -l "${LIVE_HOSTS}" \
    -t vulnerabilities/ \
    -severity medium,high,critical \
    -rate-limit "${RATE_LIMIT}" \
    -concurrency "${THREADS}" \
    -json -o "${OUTPUT_DIR}/findings/nuclei/layer3-vulns.json" \
    -silent 2>/dev/null || true
L3_COUNT=$(wc -l < "${OUTPUT_DIR}/findings/nuclei/layer3-vulns.json" 2>/dev/null || echo 0)
log "Layer 3 findings: ${L3_COUNT}"

# Layer 4: Custom templates (if available)
CUSTOM_TEMPLATES="${TOOLKIT_DIR}/templates/custom-nuclei"
if [ -d "${CUSTOM_TEMPLATES}" ] && [ "$(ls -A "${CUSTOM_TEMPLATES}" 2>/dev/null)" ]; then
    log "=== Phase 2d: Custom Template Scan ==="
    nuclei -l "${LIVE_HOSTS}" \
        -t "${CUSTOM_TEMPLATES}/" \
        -rate-limit "${RATE_LIMIT}" \
        -concurrency "${THREADS}" \
        -json -o "${OUTPUT_DIR}/findings/nuclei/layer4-custom.json" \
        -silent 2>/dev/null || true
    L4_COUNT=$(wc -l < "${OUTPUT_DIR}/findings/nuclei/layer4-custom.json" 2>/dev/null || echo 0)
    log "Layer 4 findings: ${L4_COUNT}"
fi

# ============================================================
# PHASE 3: Additional Checks
# ============================================================
log "=== Phase 3: Additional Security Checks ==="

# Subdomain takeover check
if command -v subjack &>/dev/null; then
    log "Checking subdomain takeover..."
    SUBS_FILE="${OUTPUT_DIR}/recon/subdomains-inscope.txt"
    if [ -f "${SUBS_FILE}" ]; then
        subjack -w "${SUBS_FILE}" -t "${THREADS}" -timeout 30 -ssl \
            -o "${OUTPUT_DIR}/findings/custom/subdomain-takeover.txt" \
            2>/dev/null || true
    fi
fi

# CORS misconfiguration check via nuclei
log "Checking CORS misconfigurations..."
nuclei -l "${LIVE_HOSTS}" \
    -t http/misconfiguration/cors/ \
    -rate-limit "${RATE_LIMIT}" \
    -json -o "${OUTPUT_DIR}/findings/custom/cors-misconfig.json" \
    -silent 2>/dev/null || true

# Security header check
log "Checking security headers..."
nuclei -l "${LIVE_HOSTS}" \
    -t http/misconfiguration/missing-security-headers/ \
    -severity medium,high \
    -rate-limit "${RATE_LIMIT}" \
    -json -o "${OUTPUT_DIR}/findings/custom/missing-headers.json" \
    -silent 2>/dev/null || true

# ============================================================
# PHASE 4: Aggregate and Deduplicate Findings
# ============================================================
log "=== Phase 4: Aggregating Findings ==="

python -c "
import json, os, glob

findings = []
seen = set()
findings_dir = '${OUTPUT_DIR}/findings'

for json_file in glob.glob(os.path.join(findings_dir, '**', '*.json'), recursive=True):
    try:
        with open(json_file) as f:
            for line in f:
                try:
                    finding = json.loads(line.strip())
                    # Dedup key: template-id + host
                    key = f\"{finding.get('template-id', '')}-{finding.get('host', '')}\"
                    if key not in seen:
                        seen.add(key)
                        findings.append(finding)
                except json.JSONDecodeError:
                    pass
    except: pass

# Sort by severity
severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
findings.sort(key=lambda x: severity_order.get(x.get('info', {}).get('severity', 'info'), 4))

# Write aggregated findings
output_file = os.path.join(findings_dir, 'automated-findings.json')
with open(output_file, 'w') as f:
    json.dump(findings, f, indent=2)

# Summary by severity
from collections import Counter
severity_counts = Counter(f.get('info', {}).get('severity', 'unknown') for f in findings)
print(f'Total unique findings: {len(findings)}')
for sev in ['critical', 'high', 'medium', 'low', 'info']:
    if severity_counts[sev]:
        print(f'  {sev}: {severity_counts[sev]}')
" 2>/dev/null || log "[WARN] Finding aggregation failed"

# ============================================================
# Summary
# ============================================================
log ""
log "=== Vulnerability Scan Summary ==="
TOTAL=$(python -c "import json; print(len(json.load(open('${OUTPUT_DIR}/findings/automated-findings.json'))))" 2>/dev/null || echo "unknown")
log "Total unique findings: ${TOTAL}"
log "Results: ${OUTPUT_DIR}/findings/"
log "=== Vulnerability Scan Complete ==="
