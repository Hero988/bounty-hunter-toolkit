#!/usr/bin/env bash
# Content Discovery - Directory fuzzing, endpoint extraction, JS analysis
# Usage: content_discovery.sh <live_hosts_file> <output_dir> <scope_json>

set -euo pipefail

LIVE_HOSTS="${1:?Usage: content_discovery.sh <live_hosts_file> <output_dir> <scope_json>}"
OUTPUT_DIR="${2:?Provide output directory}"
SCOPE_JSON="${3:?Provide scope.json path}"
TOOLKIT_DIR="${HOME}/.bounty-hunter-toolkit"
RATE_LIMIT="${RATE_LIMIT:-50}"
THREADS="${THREADS:-10}"
MAX_HOSTS="${MAX_HOSTS:-20}"
WORDLIST_DIR="${HOME}/.bounty-hunter-data/wordlists"

# Fallback wordlist locations
if [ ! -d "${WORDLIST_DIR}" ]; then
    WORDLIST_DIR="${HOME}/wordlists"
fi

mkdir -p "${OUTPUT_DIR}/recon/directories" "${OUTPUT_DIR}/recon/endpoints" "${OUTPUT_DIR}/logs"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "${OUTPUT_DIR}/logs/content-discovery.log"; }

log "Starting content discovery"

# Find a usable wordlist
WORDLIST=""
for wl in "${WORDLIST_DIR}/common.txt" "${WORDLIST_DIR}/raft-medium-directories.txt" "/usr/share/wordlists/dirb/common.txt"; do
    if [ -f "${wl}" ]; then
        WORDLIST="${wl}"
        break
    fi
done

if [ -z "${WORDLIST}" ]; then
    log "[WARN] No wordlist found. Skipping directory fuzzing."
    log "       Run: python ~/.bounty-hunter-toolkit/scripts/setup.py --install-missing"
fi

# ============================================================
# PHASE 1: Directory Fuzzing with ffuf
# ============================================================
log "=== Phase 1: Directory Fuzzing ==="

if command -v ffuf &>/dev/null && [ -n "${WORDLIST}" ]; then
    HOST_COUNT=0
    while IFS= read -r host; do
        HOST_COUNT=$((HOST_COUNT + 1))
        if [ "${HOST_COUNT}" -gt "${MAX_HOSTS}" ]; then
            log "Reached max hosts limit (${MAX_HOSTS}), stopping ffuf"
            break
        fi

        # Sanitize hostname for filename
        SAFE_HOST=$(echo "${host}" | sed 's|https\?://||; s|/|_|g; s|:|-|g')
        OUTFILE="${OUTPUT_DIR}/recon/directories/ffuf-${SAFE_HOST}.json"

        log "  Fuzzing: ${host}"
        ffuf -u "${host}/FUZZ" \
            -w "${WORDLIST}" \
            -mc 200,201,301,302,307,401,403,405 \
            -rate "${RATE_LIMIT}" \
            -t "${THREADS}" \
            -timeout 10 \
            -recursion-depth 1 \
            -o "${OUTFILE}" \
            -of json \
            -s 2>/dev/null || true

    done < "${LIVE_HOSTS}"
    log "Directory fuzzing complete for ${HOST_COUNT} hosts"
else
    log "[SKIP] ffuf not available or no wordlist"
fi

# ============================================================
# PHASE 2: Web Crawling with Katana
# ============================================================
log "=== Phase 2: Web Crawling ==="

if command -v katana &>/dev/null; then
    CRAWL_OUTPUT="${OUTPUT_DIR}/recon/endpoints/katana-all.txt"
    JS_OUTPUT="${OUTPUT_DIR}/recon/endpoints/js-files.txt"

    log "Running katana crawler..."
    katana -list "${LIVE_HOSTS}" \
        -depth 3 \
        -js-crawl \
        -known-files all \
        -concurrency "${THREADS}" \
        -rate-limit "${RATE_LIMIT}" \
        -silent \
        -output "${CRAWL_OUTPUT}" 2>/dev/null || true

    # Extract JS files
    if [ -f "${CRAWL_OUTPUT}" ]; then
        grep -iE '\.js(\?|$)' "${CRAWL_OUTPUT}" 2>/dev/null | sort -u > "${JS_OUTPUT}" || true
        log "Crawled URLs: $(wc -l < "${CRAWL_OUTPUT}" 2>/dev/null || echo 0)"
        log "JS files found: $(wc -l < "${JS_OUTPUT}" 2>/dev/null || echo 0)"
    fi
else
    log "[SKIP] katana not installed"
fi

# ============================================================
# PHASE 3: Parameter Extraction
# ============================================================
log "=== Phase 3: Parameter Extraction ==="

PARAMS_FILE="${OUTPUT_DIR}/recon/parameters.json"
URLS_FILE="${OUTPUT_DIR}/recon/urls.txt"

# Extract parameters from historical URLs and crawl results
python -c "
import json, re, sys
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

params_by_host = defaultdict(lambda: defaultdict(int))
all_urls = set()

# Read URL files
for filepath in ['${URLS_FILE}', '${OUTPUT_DIR}/recon/endpoints/katana-all.txt']:
    try:
        with open(filepath) as f:
            for line in f:
                url = line.strip()
                if '?' in url:
                    all_urls.add(url)
                    parsed = urlparse(url)
                    host = parsed.netloc
                    for param in parse_qs(parsed.query):
                        params_by_host[host][param] += 1
    except FileNotFoundError:
        pass

# Build output
output = {}
for host, params in sorted(params_by_host.items()):
    output[host] = {p: c for p, c in sorted(params.items(), key=lambda x: -x[1])[:50]}

with open('${PARAMS_FILE}', 'w') as f:
    json.dump(output, f, indent=2)

total_params = sum(len(v) for v in output.values())
print(f'Parameters extracted: {total_params} unique params across {len(output)} hosts')
" 2>/dev/null || log "[WARN] Parameter extraction failed"

# ============================================================
# Summary
# ============================================================
log ""
log "=== Content Discovery Summary ==="
log "Directories: ${OUTPUT_DIR}/recon/directories/"
log "Endpoints: ${OUTPUT_DIR}/recon/endpoints/"
log "Parameters: ${PARAMS_FILE}"
log "=== Content Discovery Complete ==="
