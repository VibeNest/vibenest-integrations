# Next.js App Router: Project Payments

**Status: Payments simulator preview.** This is the production-validated v1.0.8
fixture. It moves no money and must be deployed to production code only with
`VIBENEST_PROJECT_PAYMENTS_ENABLED=false`.

## Install

```bash
npm ci
```

## Run

Copy `.env.example` to `.env.local`. Disabled mode runs safely with placeholders:

```bash
npm run dev
```

Simulator values are issued write-only by VibeNest during an explicitly
authorized preview; do not invent or commit them.

## Test

```bash
npm test
npm run build
```

## Routes

- `POST /api/project-payments/prices`
- `POST /api/project-payments/checkout`
- `POST /api/project-payments/portal`
- `POST /api/project-payments/webhook`
- `POST /.well-known/vibenest/project-payments/harness`
- `GET /.well-known/vibenest/project-payments/verifier`

## Environment

All names are listed in `.env.example`: enabled/provider/verifier flags,
write-only simulator secret, environment ID, manifest digest, catalog
projection, exact `SOURCE_COMMIT`, and local fixture database path.

## Adaptation boundary

Copy the manifest, protocol validation, durable inbox, webhook raw-body reader,
and entitlement-source aggregation as a unit. Adapt `authenticatedBuyerFromRequest`
to the project's existing verified server session and replace the fixture store
with project persistence/migrations. Never accept buyer identity from JSON,
query strings, local storage, or arbitrary headers. Product/price/grant keys in
this deterministic catalog are samples, not a pricing recommendation.
