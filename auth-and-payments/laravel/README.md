# Laravel: VibeNest Auth and Project Payments

**Status: Production-ready Auth + Payments simulator preview.** The example
composes the verified Laravel Auth service with the simulator-only Payments
service. The validated pairwise OIDC `sub` stored in the Laravel session is the
only identity accepted by checkout, portal, customer mapping, and entitlements.

## Install

```bash
composer install
```

Run from the repository checkout because Composer loads the two narrow service
files from `auth/laravel` and `payments/laravel`. When adapting an application,
copy those two files into its normal `App\Services` namespace.

## Run

Copy `.env.example`, configure Auth, generate `APP_KEY`, and leave Payments
disabled until separately approved. Then run:

```bash
php artisan serve --host=0.0.0.0 --port=8080
```

## Test

```bash
composer test
php artisan route:list
```

## Routes

- `GET /auth/vibenest/login`, `GET /auth/vibenest/callback`
- `POST /auth/logout`, `GET /api/session`
- `GET /api/project-payments/prices`
- `POST /api/project-payments/checkout`
- `POST /api/project-payments/portal`
- `POST /webhooks/project-payments`
- `GET /.well-known/vibenest/project-payments/verifier`
- `GET /healthz`

## Environment

All variables from the Laravel Auth and Payments references: `APP_KEY`,
`SESSION_DRIVER`, `SESSION_SECURE_COOKIE`,
`VIBENEST_AUTH_*`, `VIBENEST_PROJECT_PAYMENTS_*`, `SOURCE_COMMIT`,
`PROJECT_PAYMENT_FIXTURE_STORE`, and `PORT`.

## Adaptation boundary

Copy the Auth and Payments services, then adapt Laravel routing, sessions,
persistence, queues, catalog keys, and UI. Preserve the single validated
pairwise-`sub` identity boundary, callback pinning, raw webhook verification,
and idempotent inbox. Payments still require separate user confirmation.
