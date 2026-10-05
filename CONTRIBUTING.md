# Contributing to Secure Authentication Service

Thank you for contributing to this educational defensive security project.

## Development Workflow

1. Create a virtual environment with Python 3.12+:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```
2. Adhere to code quality standards:
   - Ensure all code passes `ruff check .`, `ruff format --check .`, `mypy src/`, and `bandit -r src/`.
   - Maintain 85%+ test coverage (`pytest --cov=secure_auth`).
   - Use only synthetic values in test fixtures.
