# Express: VibeNest Auth + Project Payments

**Status: Production-ready Auth + Payments simulator preview.** The validated
pairwise OIDC `sub` in `express-session` is the only Payments buyer identity.
Payments stay disabled by default and no live provider operation exists here.

## Install

```bash
npm ci
```

## Run

Load Auth values from **VibeNest Project Settings -> Authorization**, configure
a durable PostgreSQL/Redis session store, and keep Payments disabled:

```bash
npm start
```

## Test

```bash
npm test
npm run build
```

## Routes

- Auth: `GET /auth/vibenest/login`, `GET /auth/vibenest/callback`, `POST
  /auth/logout`, `GET /api/session`.
- Payments: `POST /api/project-payments/prices/preview`, `POST
  /api/project-payments/checkout`, `POST /api/project-payments/portal`, `POST
  /webhooks/project-payments`.
- Simulator-only: `POST /.well-known/vibenest/project-payments/harness`, `GET
  /.well-known/vibenest/project-payments/verifier`.

## Environment

`.env.example` lists the exact Auth, trusted-proxy, session, Payments simulator,
catalog/build, database, and port settings. `VIBENEST_FIXTURE_AUTH_ENABLED` is
test-only and must never be set in a deployment.

## Adaptation boundary

Keep OIDC validation and the Project Payments protocol/inbox/entitlement slice.
Adapt session persistence, project database migrations, mounting, error UI, and
catalog keys. Checkout and portal resolve the same `request.session.user.subject`
used by Auth and require same-origin CSRF. Payments need a separate explicit
approval after simulator verification.
