# Repository Guidelines

## Project Structure & Module Organization

This Flask application administers Cloudflare Email Routing rules. `app.py` remains the Gunicorn entrypoint. The `email_app/` package contains `config.py` and services: `cloudflare.py` (API client), `rules.py` (rule operations), and `words.py` (generation). `words.txt` remains the source word list. Templates live in `templates/`; browser assets live in `static/`.

## Build, Test, and Development Commands

Create a local `.env` file with the variables documented in `README.md`; never commit it.

```bash
docker compose up --build     # build and run the production-style container on localhost:5001
python -m pip install -r requirements.txt
python app.py                 # run Flask locally on localhost:5000
python -m compileall app.py email_app  # quick syntax check
python -m pytest  # run the test suite
python -m pip_audit -r requirements.txt  # audit dependencies
```

The project uses `pytest` for regression and security coverage and `pip-audit` for dependency checks. No formatter/linter is configured; add focused `pytest` tests with new behavior, especially for pure functions in `email_app/services/rules.py`.

## Coding Style & Naming Conventions

Use Python with four-space indentation, standard-library imports before third-party imports, `snake_case` for functions and variables, and `UPPER_SNAKE_CASE` for configuration constants. Keep routes in `app.py` thin and place Cloudflare behavior in `email_app/services/`. Prefer small helpers that return explicit success values or `None` on failure. Use descriptive Flask endpoint functions such as `delete_rule` and `get_emails`. Keep template filenames lowercase and update `static/style.css` for UI changes rather than embedding substantial styles in templates.

## Testing Guidelines

Name test files `test_<module>.py` and tests `test_<behavior>()`. Mock `requests` for Cloudflare calls; tests must not require real credentials or modify live routing rules. Run tests with `python -m pytest` once a test suite is added. At minimum, cover successful and failed API responses plus edge cases in parsing and generated-email handling.

## Commit & Pull Request Guidelines

Recent history favors short imperative subjects, commonly `fix: <change>` (for example, `fix: update requirements.txt`); use that convention consistently. Keep commits scoped to one change. Pull requests should explain the user-visible or operational impact, list validation performed, link the relevant issue when available, and include screenshots for changes to templates or styling. Call out any new environment variable, Docker change, or Cloudflare permission requirement explicitly.

## Security & Configuration

Treat `SECRET_KEY`, Cloudflare tokens, password hashes, and email addresses as secrets. Source them only from environment variables, redact them from logs and screenshots, and use a least-privilege Cloudflare token for the target zone.
