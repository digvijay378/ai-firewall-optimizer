"""
AI Firewall Policy Optimizer - Core Analyzer

Detects:
- Shadowed rules
- Redundant / duplicate logic
- Overly permissive rules (broad sources/dests/services)
- High-risk rules (no logging, any/any, etc.)
- Unused rules (zero hits over long period)

Designed for Palo Alto-style rule exports but easily extended to other vendors.
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
    comment: str = ""

    def is_any_any(self) -> bool:
        return (
            self.source.lower() in ("any", "0.0.0.0/0", "all") or
            self.destination.lower() in ("any", "0.0.0.0/0", "all") or
            self.service.lower() == "any"
        )

    def is_permissive(self) -> bool:
        """Heuristic for overly broad rules."""
        broad_indicators = 0
        for field in (self.source, self.destination):
            if any(x in field.lower() for x in ["any", "0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]):
                broad_indicators += 1
        return broad_indicators >= 1 or self.service.lower() == "any"

    def risk_score(self) -> int:
        """Higher = more dangerous / needs review."""
        score = 0
        if self.is_any_any():
            score += 60
        elif self.is_permissive():
            score += 35
        if self.log.lower() not in ("yes", "log", "true", "1"):
            score += 15
        if self.hit_count == 0:
            score += 10
        if self.action.lower() == "allow":
            score += 10
        return min(score, 100)


class FirewallAnalyzer:
    def __init__(self, rules: List[Rule]):
        self.rules = rules

    def find_shadowed_rules(self) -> List[Dict]:
        """Detect rules that are effectively unreachable because of earlier broader rules."""
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
        a_broad = a.source.lower() in ("any", "0.0.0.0/0") or a.destination.lower() in ("any", "0.0.0.0/0")
        b_specific = b.source.lower() not in ("any", "0.0.0.0/0") and b.destination.lower() not in ("any", "0.0.0.0/0")
        return a_broad and b_specific

    def find_redundant(self) -> List[Dict]:
        """Exact duplicates of (src, dst, svc, action)."""
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

    def find_unused(self, min_days: int = 90) -> List[Rule]:
        """Rules with zero hits that are allows."""
        return [r for r in self.rules if r.hit_count == 0 and r.action.lower() == "allow"]

    def analyze(self, min_risk: int = 70) -> Dict:
        shadowed = self.find_shadowed_rules()
        redundant = self.find_redundant()
        high_risk = sorted(
            [r for r in self.rules if r.risk_score() >= min_risk],
            key=lambda r: r.risk_score(),
            reverse=True
        )
        unused = self.find_unused()

        recommendations = self._generate_recommendations(high_risk, shadowed)

        return {
            "total_rules": len(self.rules),
            "shadowed": shadowed,
            "redundant": redundant,
            "high_risk": high_risk,
            "unused": unused,
            "recommendations": recommendations,
        }

    def _generate_recommendations(self, high_risk: List[Rule], shadowed: List[Dict]) -> List[str]:
        recs = []
        if high_risk:
            recs.append(f"Review and tighten the {len(high_risk)} highest-risk rules first.")
        if shadowed:
            recs.append(f"Remove or reorder {len(shadowed)} shadowed rules that will never match.")
        if any(r.hit_count == 0 for r in high_risk):
            recs.append("Consider deleting or disabling rules with zero hits in the last 90 days.")
        return recs

    def print_summary(self, analysis: Dict):
        console.rule("[bold red]Firewall Policy Analysis Summary")
        console.print(f"Total rules analyzed: [bold]{analysis['total_rules']}[/bold]")
        console.print("[dim]Tip: use --format json for automation / ticketing systems[/dim]")

        if analysis["high_risk"]:
            table = Table(title=f"High Risk Rules (Score ≥ 70) — Top {min(10, len(analysis['high_risk']))}")
            table.add_column("Rule", style="cyan")
            table.add_column("Risk", style="red")
            table.add_column("Issues", style="yellow")
            for r in analysis["high_risk"][:10]:
                issues = []
                if r.is_any_any(): issues.append("any/any")
                if r.is_permissive(): issues.append("overly broad")
                if r.hit_count == 0: issues.append("0 hits")
                if r.log.lower() not in ("yes", "log"): issues.append("no logging")
                table.add_row(r.name, str(r.risk_score()), ", ".join(issues) or "review manually")
            console.print(table)

        if analysis["shadowed"]:
            console.print(f"\n[bold yellow]Shadowed rules:[/bold yellow] {len(analysis['shadowed'])}")
            for s in analysis["shadowed"][:5]:
                console.print(f"  - {s['shadowed_rule']} shadowed by {s['by_rule']}")

        if analysis["redundant"]:
            console.print(f"\n[bold yellow]Exact duplicate rules:[/bold yellow] {len(analysis['redundant'])}")

        if analysis["unused"]:
            console.print(f"\n[bold]Unused allow rules (0 hits):[/bold] {len(analysis['unused'])}")

        if analysis.get("recommendations"):
            console.print("\n[green]Key Recommendations:[/green]")
            for rec in analysis["recommendations"]:
                console.print(f"  • {rec}")


def load_rules_from_csv(path: str) -> List[Rule]:
    """Load rules from a CSV export (supports common Panorama / firewall column names)."""
    df = pd.read_csv(path)
    rules = []
    for _, row in df.iterrows():
        rules.append(Rule(
            name=str(row.get("name", row.get("Rule Name", "unnamed"))).strip(),
            source=str(row.get("source", row.get("Source", "any"))).strip(),
            destination=str(row.get("destination", row.get("Destination", "any"))).strip(),
            service=str(row.get("service", row.get("Service", "any"))).strip(),
            action=str(row.get("action", row.get("Action", "allow"))).lower().strip(),
            log=str(row.get("log", row.get("Log", "no"))).strip(),
            hit_count=int(row.get("hit_count", row.get("Hit Count", 0)) or 0),
            comment=str(row.get("comment", row.get("Comment", ""))).strip(),
        ))
    return rules


def load_hits_from_csv(path: str) -> Dict[str, int]:
    """Load hit counts separately (useful when rules export and hits are in different reports)."""
    df = pd.read_csv(path)
    # Assume first column is rule name, second is hits
    return dict(zip(df.iloc[:, 0].astype(str), df.iloc[:, 1].astype(int)))
