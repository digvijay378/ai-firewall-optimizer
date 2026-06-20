"""
AI Firewall Policy Optimizer - Core Analyzer

Detects:
- Shadowed rules
- Redundant / duplicate logic
- Overly permissive rules (broad sources/dests/services)
- High-risk rules (no logging, any/any, etc.)

Designed for Palo Alto-style rule exports but easily extended.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional
import pandas as pd
from rich.console import Console
from rich.table import Table

console = Console()

@dataclass
class Rule:
    name: str
    source: str
    destination: str
    service: str
    action: str
    log: str = "no"
    hit_count: int = 0
    zone_from: str = ""
    zone_to: str = ""

    def is_any_any(self) -> bool:
        return (
            self.source.lower() in ("any", "0.0.0.0/0", "all") or
            self.destination.lower() in ("any", "0.0.0.0/0", "all") or
            self.service.lower() == "any"
        )

    def is_permissive(self) -> bool:
        # Simple heuristic: any/any or very broad
        broad_indicators = 0
        for field in (self.source, self.destination):
            if any(x in field.lower() for x in ["any", "0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16"]):
                broad_indicators += 1
        return broad_indicators >= 1 or self.service.lower() == "any"

    def risk_score(self) -> int:
        score = 0
        if self.is_any_any():
            score += 60
        elif self.is_permissive():
            score += 35
        if self.log.lower() not in ("yes", "log", "true", "1"):
            score += 15
        if self.hit_count == 0:
            score += 10
        # Action allow is default risk
        if self.action.lower() == "allow":
            score += 10
        return min(score, 100)


class FirewallAnalyzer:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def find_shadowed_rules(self) -> List[Dict]:
        """Naive shadowing detection: later rules that would be matched by earlier broader rules."""
        shadowed = []
        for i, later in enumerate(self.rules):
            for earlier in self.rules[:i]:
                if self._is_broader(earlier, later) and earlier.action == later.action:
                    shadowed.append({
                        "shadowed_rule": later.name,
                        "by_rule": earlier.name,
                        "reason": "Broader source/dest/service earlier in rulebase"
                    })
                    break
        return shadowed

    def _is_broader(self, a: Rule, b: Rule) -> bool:
        # Very simplified: treat "any" as broader than specific
        a_broad = a.source.lower() in ("any", "0.0.0.0/0") or a.destination.lower() in ("any", "0.0.0.0/0")
        b_specific = b.source.lower() not in ("any", "0.0.0.0/0") and b.destination.lower() not in ("any", "0.0.0.0/0")
        return a_broad and b_specific

    def find_redundant(self) -> List[Dict]:
        """Find rules with identical source/dest/service/action."""
        seen = {}
        redundant = []
        for rule in self.rules:
            key = (rule.source.lower(), rule.destination.lower(), rule.service.lower(), rule.action.lower())
            if key in seen:
                redundant.append({
                    "rule": rule.name,
                    "duplicate_of": seen[key]
                })
            else:
                seen[key] = rule.name
        return redundant

    def analyze(self) -> Dict:
        shadowed = self.find_shadowed_rules()
        redundant = self.find_redundant()

        high_risk = sorted(
            [r for r in self.rules if r.risk_score() > 70],
            key=lambda r: r.risk_score(),
            reverse=True
        )

        unused = [r for r in self.rules if r.hit_count == 0 and r.action == "allow"]

        return {
            "total_rules": len(self.rules),
            "shadowed": shadowed,
            "redundant": redundant,
            "high_risk": high_risk,
            "unused": unused,
        }

    def print_summary(self, analysis: Dict):
        console.rule("[bold red]Firewall Policy Analysis Summary")
        console.print(f"Total rules analyzed: [bold]{analysis['total_rules']}[/bold]")
        console.print("[dim]Tip: pipe to --format json for automation pipelines[/dim]")

        if analysis["high_risk"]:
            table = Table(title="High Risk Rules (Score > 70)")
            table.add_column("Rule", style="cyan")
            table.add_column("Risk", style="red")
            table.add_column("Issues")
            for r in analysis["high_risk"][:10]:
                issues = []
                if r.is_any_any(): issues.append("any/any")
                if r.is_permissive(): issues.append("overly broad")
                if r.hit_count == 0: issues.append("zero hits")
                table.add_row(r.name, str(r.risk_score()), ", ".join(issues) or "check logging")
            console.print(table)

        if analysis["shadowed"]:
            console.print(f"\n[bold yellow]Shadowed rules found:[/bold yellow] {len(analysis['shadowed'])}")
            for s in analysis["shadowed"][:5]:
                console.print(f"  - {s['shadowed_rule']} shadowed by {s['by_rule']}")

        if analysis["redundant"]:
            console.print(f"\n[bold yellow]Redundant rules:[/bold yellow] {len(analysis['redundant'])}")

        if analysis["unused"]:
            console.print(f"\n[bold]Unused allow rules (0 hits):[/bold] {len(analysis['unused'])}")

        console.print("\n[green]Recommendations:[/green] Review high-risk and shadowed rules first.")


def load_rules_from_csv(path: str) -> List[Rule]:
    df = pd.read_csv(path)
    rules = []
    for _, row in df.iterrows():
        rules.append(Rule(
            name=str(row.get("name", row.get("Rule Name", "unnamed"))),
            source=str(row.get("source", row.get("Source", "any"))),
            destination=str(row.get("destination", row.get("Destination", "any"))),
            service=str(row.get("service", row.get("Service", "any"))),
            action=str(row.get("action", row.get("Action", "allow"))).lower(),
            log=str(row.get("log", row.get("Log", "no"))),
            hit_count=int(row.get("hit_count", row.get("Hit Count", 0)) or 0),
        ))
    return rules
