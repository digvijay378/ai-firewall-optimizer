"""
Unit tests for the Firewall Policy Analyzer.

Run with: pytest
"""

import pytest
from pathlib import Path
import sys

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from firewall_analyzer import Rule, FirewallAnalyzer, load_rules_from_csv


def test_rule_any_any_detection():
    r = Rule(name="bad", source="any", destination="any", service="any", action="allow")
    assert r.is_any_any() is True
    assert r.risk_score() >= 70


def test_rule_permissive_detection():
    r = Rule(name="broad", source="10.0.0.0/8", destination="192.168.0.0/16", service="any", action="allow")
    assert r.is_permissive() is True


def test_risk_score_zero_hits_no_log():
    r = Rule(name="risky", source="internal", destination="db", service="sql", action="allow", log="no", hit_count=0)
    score = r.risk_score()
    assert score > 20


def test_shadowed_detection():
    rules = [
        Rule("allow-all", "any", "any", "any", "allow"),
        Rule("specific-web", "10.10.1.0/24", "web-servers", "https", "allow"),
    ]
    analyzer = FirewallAnalyzer(rules)
    shadowed = analyzer.find_shadowed_rules()
    assert len(shadowed) >= 1
    assert "specific-web" in shadowed[0]["shadowed_rule"]


def test_redundant_detection():
    rules = [
        Rule("r1", "a", "b", "http", "allow"),
        Rule("r2", "a", "b", "http", "allow"),  # duplicate
    ]
    analyzer = FirewallAnalyzer(rules)
    redundant = analyzer.find_redundant()
    assert len(redundant) == 1


def test_load_from_csv(tmp_path):
    csv_content = "name,source,destination,service,action,log,hit_count\n"
    csv_content += "test-rule,internal,external,https,allow,yes,42\n"
    csv_file = tmp_path / "test.csv"
    csv_file.write_text(csv_content)

    rules = load_rules_from_csv(str(csv_file))
    assert len(rules) == 1
    assert rules[0].name == "test-rule"
    assert rules[0].hit_count == 42


def test_analyze_high_risk():
    rules = [
        Rule("any-any", "any", "any", "any", "allow", log="no", hit_count=0),
        Rule("good-rule", "10.0.1.0/24", "app", "tcp-443", "allow", log="yes", hit_count=1200),
    ]
    analyzer = FirewallAnalyzer(rules)
    result = analyzer.analyze()
    assert result["total_rules"] == 2
    assert len(result["high_risk"]) >= 1
    assert any("any-any" in r.name for r in result["high_risk"])
