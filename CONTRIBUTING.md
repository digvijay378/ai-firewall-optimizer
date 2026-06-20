# Contributing

Thanks for your interest!

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install pytest
pytest
```

## Adding new rule parsers

Create a new loader in `parsers/` (future) and add tests.

## Reporting new issues

Please include:
- Sample (anonymized) rule export
- Expected vs actual behavior
- Python version

## Code style

Keep it simple. Use rich for terminal output. Add tests for new detection logic.
