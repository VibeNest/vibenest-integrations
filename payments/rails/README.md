# Rails: VibeNest Project Payments

**Status: Payments simulator preview.** No live-charge or production-deploy path
exists. The Rails slice shows a trusted catalog, server-session identity,
simulator checkout/portal URLs, exact raw-body HMAC verification, durable SQLite
inbox, duplicate delivery handling, and entitlement projection.

## Install

```bash
bundle config set path vendor/bundle
bundle install
```

## Run

Copy `.env.example`, keep `simulator`, connect the existing Rails session to
`user.subject`, then run:

```bash
bundle exec rails server -b 0.0.0.0 -p 8080
```

## Test

```bash
bundle exec rails test
bundle exec rails routes
```

## Routes

- `GET /api/project-payments/prices`
- `POST /api/project-payments/checkout`
- `POST /api/project-payments/portal`
- `POST /webhooks/project-payments`
- `GET /.well-known/vibenest/project-payments/verifier`
- `GET /healthz`

## Environment

- `SECRET_KEY_BASE`
- `VIBENEST_PROJECT_PAYMENTS_ENABLED`
- `VIBENEST_PROJECT_PAYMENTS_PROVIDER`
- `VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED`
- `VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET`
- `VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID`
- `VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST`
- `SOURCE_COMMIT`, `PROJECT_PAYMENT_FIXTURE_STORE`, `PORT`

## Adaptation boundary

Keep raw-body verification, idempotency, environment binding, trusted catalog,
and customer-to-pairwise-`sub` mapping. Adapt persistence, Active Job, catalog
keys, and the existing session adapter. Never accept browser-authored buyer IDs.
Payments require separate user confirmation.
