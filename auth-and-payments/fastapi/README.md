# FastAPI: VibeNest Auth and Project Payments

**Status: Production-ready Auth + Payments simulator preview.** The combined
ASGI app composes the two narrow FastAPI routers without a second identity
model. The validated pairwise OIDC `sub` stored in the signed session is the
only identity passed to checkout, portal, customer mapping, and entitlements.

## Install

From this directory in a repository checkout:

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.lock
```

Set `PYTHONPATH` to the sibling `auth/fastapi/app` and
`payments/fastapi/app` directories. In a real application, copy the two modules
into its package rather than retaining this reference layout.

## Run

Copy `.env.example`, configure Auth, and keep Payments disabled until separately
approved:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## Test

```bash
pytest -q
python -m compileall -q app tests
```

## Routes

- `GET /auth/vibenest/login`, `GET /auth/vibenest/callback`
- `POST /auth/logout`, `GET /api/session`
- `GET /api/project-payments/prices`
- `POST /api/project-payments/checkout`
- `POST /api/project-payments/portal`
- `POST /webhooks/project-payments`
- `GET /.well-known/vibenest/project-payments/verifier`

## Environment

All FastAPI Auth and Payments variables: `VIBENEST_AUTH_*`,
`APP_SESSION_SECRET`, `VIBENEST_PROJECT_PAYMENTS_*`, `SOURCE_COMMIT`,
`PROJECT_PAYMENT_FIXTURE_STORE`, and `PORT`.

## Adaptation boundary

Copy the Auth and Payments modules and adapt routing, sessions, persistence,
queues, catalog keys, proxy allowlists, and UI. Preserve the validated
pairwise-`sub` identity, callback pinning, exact webhook verification, and
idempotent inbox. Payments still require separate user confirmation.
