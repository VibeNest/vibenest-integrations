# Next.js App Router: VibeNest Auth + Project Payments

**Status: Production-ready Auth + Payments simulator preview.** The same
validated pairwise OIDC `sub` stored in the application session is the sole
`buyer_subject` for checkout, portal, and entitlements. Payments are disabled by
default and this reference never enables live money movement.

## Install

```bash
npm ci
```

## Run

Fill Auth values from **VibeNest Project Settings -> Authorization**. Keep
Payments disabled until a separate, explicit simulator approval:

```bash
npm run dev
```

## Test

```bash
npm test
npm run build
```

## Routes

- Auth: `GET /auth/vibenest/login`, `GET /auth/vibenest/callback`, `POST
  /auth/logout`, `GET /api/session`.
- Payments: `POST /api/project-payments/prices`, `POST
  /api/project-payments/checkout`, `POST /api/project-payments/portal`, `POST
  /api/project-payments/webhook`.
- Simulator-only: `POST /.well-known/vibenest/project-payments/harness`, `GET
  /.well-known/vibenest/project-payments/verifier`.

## Environment

`.env.example` is the exact union of Auth, local session, Payments simulator,
catalog/build binding, and database path settings. `VIBENEST_FIXTURE_AUTH_ENABLED`
is test-only and must never be set in a deployed app.

## Adaptation boundary

Keep the OIDC validation and Project Payments protocol/inbox/entitlement code.
Adapt the encrypted session and persistence to project-owned stores, migrations,
routes, and UI. Payment POSTs validate same-origin CSRF and obtain identity only
from the Auth session. Product/catalog samples are not pricing advice. A real
Payments rollout requires a separate user confirmation after simulator success.
