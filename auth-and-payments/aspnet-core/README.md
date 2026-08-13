# ASP.NET Core: VibeNest Auth + Project Payments

**Status: Production-ready Auth + Payments simulator preview.** The validated
OIDC `sub` in the ASP.NET Core application cookie is the same subject used by
checkout, portal, and entitlement checks. Payments remain disabled by default
and the provider implementation cannot move live money.

## Install

```bash
dotnet restore --locked-mode
```

## Run

Load Auth values from **VibeNest Project Settings -> Authorization**, persist
Data Protection keys, and keep Payments disabled:

```bash
dotnet run --project ProjectPaymentsFixture.csproj
```

## Test

```bash
dotnet run --project tests/FixtureTests.csproj
dotnet test auth-tests/AuthFlowTests.csproj
dotnet build -c Release --no-restore
```

## Routes

- Auth: `GET /auth/vibenest/login`, `GET /auth/vibenest/callback`, `POST
  /auth/logout`, `GET /api/session`.
- Payments: `GET /api/project-payments/prices`, `POST
  /api/project-payments/checkout`, `POST /api/project-payments/portal`, `GET
  /api/project-payments/entitlements/{grantKey}`, `POST
  /webhooks/project-payments`.
- Simulator-only: `POST /.well-known/vibenest/project-payments/harness`, `GET
  /.well-known/vibenest/project-payments/verifier`.

## Environment

`.env.example` lists the exact Auth and Payments settings. The fixture auth
header is enabled only by `VIBENEST_FIXTURE_AUTH_ENABLED=true` in isolated tests
and must never be configured in a deployment.

## Adaptation boundary

Keep the OIDC handler and `ProjectPayments/` protocol, durable inbox,
persistence, and entitlement-source logic. Adapt Data Protection/database
persistence, routes, UI, and catalog keys. Payment POSTs require ASP.NET
antiforgery and use only the principal's pairwise `sub`. A real Payments rollout
requires separate approval after simulator verification.
