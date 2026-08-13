# Laravel: VibeNest Project Payments

**Status: Payments simulator preview.** No route can charge money or deploy a
live payment configuration. The reference shows trusted catalog lookup,
Laravel-session identity injection, simulator checkout/portal URLs, exact
raw-body HMAC verification, a durable SQLite inbox, duplicate handling, and
entitlement projection.

## Install

```bash
composer install
```

## Run

Copy `.env.example`, keep `simulator`, connect the existing authenticated
session to `user.subject`, generate `APP_KEY`, then run:

```bash
php artisan serve --host=0.0.0.0 --port=8080
```

## Test

```bash
composer test
php artisan route:list
```

## Routes

- `GET /api/project-payments/prices`
- `POST /api/project-payments/checkout`
- `POST /api/project-payments/portal`
- `POST /webhooks/project-payments`
- `GET /.well-known/vibenest/project-payments/verifier`

## Environment

- `APP_KEY`, `SESSION_DRIVER`, `SESSION_SECURE_COOKIE`
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

Keep raw-body verification, idempotency, environment binding, catalog lookup,
and the customer-to-pairwise-`sub` mapping. Adapt persistence, queues, catalog
keys, and the existing Laravel session model. Never accept a browser-authored
buyer ID. Payments require separate user confirmation.
