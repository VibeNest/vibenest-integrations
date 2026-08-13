# Rails: VibeNest Auth and Project Payments

**Status: Production-ready Auth + Payments simulator preview.** The combined
Rails app composes the two narrow services without a second user model. The
validated pairwise OIDC `sub` in the Rails session is the sole identity for
checkout, portal, customer binding, and entitlement projection.

## Install

```bash
bundle config set path vendor/bundle
bundle install
```

Run from a repository checkout because Rails autoloads the Auth and Payments
services from the sibling reference directories. In a real app, copy both
services into its normal `app/services` directory.

## Run

Copy `.env.example`, configure Auth and `SECRET_KEY_BASE`, and leave Payments
disabled until separately approved:

```bash
bundle exec rails server -b 0.0.0.0 -p 8080
```

## Test

```bash
bundle exec rails test
bundle exec rails routes
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

All Rails Auth and Payments variables: `SECRET_KEY_BASE`,
`VIBENEST_AUTH_*`, `VIBENEST_PROJECT_PAYMENTS_*`,
`SOURCE_COMMIT`, `PROJECT_PAYMENT_FIXTURE_STORE`, and `PORT`.

## Adaptation boundary

Copy the two services, then adapt controllers, sessions, persistence, Active
Job, catalog keys, and UI. Preserve the single pairwise-`sub` identity,
callback pinning, exact raw-body verification, and idempotent inbox. Payments
still require separate user confirmation.
