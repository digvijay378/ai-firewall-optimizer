# AI Firewall Policy Optimizer

Intelligent analyzer for Palo Alto (and similar NGFW) firewall policies. Detects redundant, shadowed, overly-permissive, and unused rules, then suggests safe cleanups.

Built from real-world experience optimizing rulebases at scale for financial institutions.

## Why this exists

Large enterprise firewalls often accumulate thousands of rules over years. Manual reviews are slow, error-prone, and rarely catch everything. This tool helps you:

- Find **shadowed / redundant** rules that will never match
- Identify **overly permissive** rules (any/any, broad subnets)
- Detect **unused rules** based on hit count data
- Generate prioritized remediation recommendations
- Export clean, auditable reports

## Features

- CSV / JSON rule import (export from Panorama or firewall)
- Shadowing + redundancy detection
- Risk scoring (based on source/dest/service breadth + logging state)
- Least-privilege recommendations
- Markdown + JSON report output
- CLI + importable as a library

## Quick Start

```bash
python -m pip install -r requirements.txt

# Analyze a rules export
python main.py --rules sample_rules.csv --hits sample_hits.csv --output report.md

# Get JSON for automation / tickets
python main.py --rules sample_rules.csv --format json > recommendations.json
```

## Example Output

```markdown
## High Risk Rules (Priority 1)

| Rule Name | Issue | Recommendation | Risk Score |
|-----------|-------|----------------|------------|
| Allow-All-Internal | Overly permissive (any/any) | Restrict to specific apps + zones | 92 |
| Old-Admin-Access | Shadowed by newer rule | Remove or tighten | 78 |
```

## Input Formats

The tool expects two CSVs (or you can extend the parsers):

- `rules.csv`: Rule name, source, destination, service, action, log, hit_count (optional)
- `hits.csv`: Rule name + 30/60/90 day hit counts (from Panorama or firewall)

## Roadmap

- [ ] Support direct Panorama API pull
- [ ] Palo Alto + Fortinet + Check Point parsers
- [ ] Integration with ticketing (ServiceNow/Jira)
- [ ] AI-assisted rule rewrite suggestions (LangChain)

## Background

Developed while building production AI-driven firewall governance platforms. The techniques here reduced policy review time by 60%+ and cleaned tens of thousands of legacy rules in real deployments.

## License

MIT — use it, improve it, don't blame me if you break your firewall (test in lab first).

## Author

Digvijay Parmar — Senior Security Consulting Engineer focused on AI + Zero Trust + SASE.