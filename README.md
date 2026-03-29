# Bounty Hunter Toolkit

Scripts, references, payloads, and automation for the [bounty-hunter](https://github.com/gissu/bounty-hunter) Claude Code skill.

## What's Inside

```
scripts/          12 Python/Bash scripts for the full hunting pipeline
references/       21 reference files covering 20+ vulnerability classes
  vuln-classes/   8 files - testing checklists, payloads, bypass techniques
  methodology/    4 files - recon playbook, manual testing, chain building
  platforms/      4 files - HackerOne, Bugcrowd, Intigriti, Immunefi guides
  report-templates/ 4 files - platform-specific report templates
  payloads/       5 files - curated payloads (XSS, SQLi, SSRF, SSTI, prompt injection)
templates/        Custom nuclei templates
```

## Installation

This toolkit is automatically cloned by the `bounty-hunter` skill. Manual install:

```bash
git clone https://github.com/gissu/bounty-hunter-toolkit ~/.bounty-hunter-toolkit
```

## Setup

```bash
# Install required security tools
python ~/.bounty-hunter-toolkit/scripts/setup.py --install-missing

# Check health
python ~/.bounty-hunter-toolkit/scripts/health_check.py

# Update tools and templates
python ~/.bounty-hunter-toolkit/scripts/update.py --all
```

## Required Tools

**Core (Tier 1):** nuclei, subfinder, httpx, ffuf, katana, nmap

**Extended (Tier 2):** dalfox, gau, waybackurls, assetfinder, subjack, dnsx, naabu, interactsh-client

## Updating

```bash
cd ~/.bounty-hunter-toolkit && git pull
```

## License

Apache-2.0
