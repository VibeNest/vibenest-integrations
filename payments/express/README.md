# Express: Project Payments

**Status: Payments simulator preview.** This is the production-validated v1.0.8
fixture. It performs no live checkout or charge. Production code keeps Payments
disabled.

## Install

```bash
npm ci
```

## Run

Load `.env.example` placeholders and run disabled mode:

```bash
npm start
```

## Test

```bash
npm test
npm run build
```

## Routes

- `POST /api/project-payments/prices/preview`
- `POST /api/project-payments/checkout`
- `POST /api/project-payments/portal`
- `POST /webhooks/project-payments`
- `POST /.well-known/vibenest/project-payments/harness`
- `GET /.well-known/vibenest/project-payments/verifier`

## Environment

See `.env.example` for the exact flags, write-only simulator configuration,
catalog projection, manifest/build binding, and fixture store path.

## Adaptation boundary

Copy `project-payments.mjs`, the manifest, migrations, durable inbox, signature
verification, and entitlement aggregation together. Replace
`fixtureOnlyHeaderIdentityResolver` with the project's verified server-side
session resolver before use. The browser never chooses `buyer_subject`.
Catalog values are deterministic simulator samples, not a monetization model.
