#!/bin/bash
# Example usage of the AI Firewall Policy Optimizer

echo "Running analysis on sample rules..."
python main.py --rules sample_rules.csv --output sample_report.md

echo "Generated sample_report.md"
cat sample_report.md
