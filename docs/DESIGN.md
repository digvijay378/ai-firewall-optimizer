# Design Notes — AI Firewall Policy Optimizer

## Goals

- Help security teams reduce rulebase bloat safely.
- Surface real risk instead of just "lots of rules".
- Be usable both interactively and in automated pipelines (JSON output).

## Core Heuristics

1. **Shadowing**: A later specific rule is shadowed if an earlier rule with broader src/dst/svc would have matched first.
2. **Redundancy**: Exact match on the 4-tuple (src, dst, service, action).
3. **Risk scoring** (0-100):
   - any/any → +60
   - overly broad (large subnets, any service) → +35
   - no logging enabled → +15
   - zero hit count → +10
   - allow action → +10

These numbers are tuned from real enterprise cleanup projects.

## Limitations (current)

- No deep object group resolution (yet).
- No understanding of NAT or routing.
- Shadow detection is conservative (better false positives than missing real shadows).

## Future ideas

- Integrate with Panorama / FortiManager APIs for live data.
- Use LLM to suggest rewritten tighter rules.
- Generate actual change tickets.
