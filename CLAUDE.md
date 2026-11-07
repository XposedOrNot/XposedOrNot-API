# XposedOrNot API - working notes

FastAPI on Cloud Run, Google Cloud Datastore + Redis. Routes in `api/v1/`, business logic in `services/`, response models in `models/responses.py`, validation helpers in `utils/validation.py`, tests in `tests/`.

## Tooling (pytest is NOT on PATH)
- pytest: `~/venv/bin/python -m pytest`
- black: `black <changed files>`
- pylint, per change: `pylint <changed files>`
- pylint, same as CI (push-ready gate only, ~25 s): `pylint --fail-under=9 $(git ls-files '*.py' | grep -v '^.github/fuzz/')`

## Tests
- always pass `-m "not live"`; the `live` marker hits the deployed API.
- fast offline suite, run it per change in coding mode: `~/venv/bin/python -m pytest -m "not live" -q` (~5 s for ~140 tests as of 2026-11-07).
- if the run ever stalls, it is the breach-catalog cold-start query (`services/breach_catalog.py`) waiting on an unreachable Datastore (60 s per hit). then run only the touched test file(s), e.g. `~/venv/bin/python -m pytest tests/test_unsubscribe.py -q`, and finish the full run at the push-ready gate.
- tests stub Datastore per file with small in-memory clients (pattern: `tests/test_unsubscribe.py`); follow that pattern, never hit real Datastore/Redis/Mailjet from tests.
- baseline for comparison: the last green run before the batch started. do not re-run a baseline per change.

## Repo facts that are easy to get wrong
- prod deploys from the working tree, so uncommitted changes ship.
- Redis is pinned to `redis==8.0.0`; the rate limiter fails degraded (in-memory fallback) when Redis is down.
- real client IP is `CF-Connecting-IP`; `request.client.host` is Google's frontend.
- the monthly digest scheduler trigger is intentionally commented out; do not re-enable or flag it.
- the ghcr image is private by design.
