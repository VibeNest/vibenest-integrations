# FastAPI: VibeNest Project Payments

**Status: Payments simulator preview.** This slice contains no live charge or
production deployment path. It demonstrates trusted catalog lookup, an injected
server identity, simulator checkout/portal URLs, exact raw-body signature
verification, a durable idempotent SQLite inbox, and entitlement projection.

## Install

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.lock
```

## Run

Copy `.env.example`, keep the provider set to `simulator`, connect
`existing_application_identity()` to the existing server-side session, then run:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## Test

```bash
pytest -q
python -m compileall -q app tests
```

## Routes

- `GET /api/project-payments/prices`
- `POST /api/project-payments/checkout`
- `POST /api/project-payments/portal`
- `POST /webhooks/project-payments`
- `GET /.well-known/vibenest/project-payments/verifier`

## Environment

- `VIBENEST_PROJECT_PAYMENTS_ENABLED`
- `VIBENEST_PROJECT_PAYMENTS_PROVIDER`
- `VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED`
- `VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET`
- `VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID`
- `VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST`
- `SOURCE_COMMIT`
- `PROJECT_PAYMENT_FIXTURE_STORE`
- `PORT`

## Adaptation boundary

Keep raw-body verification, event idempotency, environment binding, server-owned
catalog lookup, and the customer-to-pairwise-`sub` mapping. Adapt persistence,
background processing, product keys, and the existing session adapter. Never
accept a browser-authored buyer ID. Payments require separate user confirmation.
