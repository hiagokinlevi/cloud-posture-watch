# Contributing to cloud-posture-watch

Thank you for considering a contribution. This document describes how to get started, coding conventions, and the pull request process.

---

## Getting started

1. **Fork** the repository and clone your fork locally.
2. Create a virtual environment and install development dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. Create a feature branch from `main`:

   ```bash
   git checkout -b feat/your-feature-name
   ```

---

## Types of contributions

- **Bug fixes** — check open issues labelled `bug`
- **New provider collectors** — follow the pattern in `providers/aws/storage_collector.py`
- **New baseline rules** — edit or add YAML files under `baselines/`
- **Documentation** — improvements to `docs/` or inline docstrings
- **Tests** — additional unit or integration tests in `tests/`

---

## Coding conventions

- Python 3.11+ — use modern type hints (`list[str]`, `str | None`, etc.)
- All public functions must have docstrings
- Use `structlog` for logging, not `print`
- Pydantic models live in `schemas/`; dataclasses are acceptable inside modules
- Format with `black`, lint with `ruff`: `make lint`
- All new modules must have a corresponding test file

---

## Pull request checklist

- [ ] Tests pass: `pytest`
- [ ] Linting passes: `make lint`
- [ ] New code has docstrings and inline comments on non-obvious logic
- [ ] Credentials are never logged, stored, or transmitted
- [ ] PR description explains the motivation and links to any related issue

---

## Commit message style

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add GCP VPC flow log collector
fix: handle missing public access block config in older S3 buckets
docs: clarify required IAM permissions for Azure assessments
```

---

## Code of Conduct

All contributors are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
