# ASP.NET Core: Project Payments

**Status: Payments simulator preview.** This is the production-validated v1.0.8
fixture. It moves no money. Production code is eligible only with Payments
disabled.

## Install

```bash
dotnet restore --locked-mode
```

## Run

Load `.env.example` placeholders and run safely in disabled mode:

```bash
dotnet run --project ProjectPaymentsFixture.csproj
```

## Test

```bash
dotnet run --project tests/FixtureTests.csproj
dotnet build -c Release --no-restore
```

## Routes

- `GET /api/project-payments/prices`
- `POST /api/project-payments/checkout`
- `POST /api/project-payments/portal`
- `GET /api/project-payments/entitlements/{grantKey}`
- `POST /webhooks/project-payments`
- `POST /.well-known/vibenest/project-payments/harness`
- `GET /.well-known/vibenest/project-payments/verifier`

## Environment

See `.env.example` for the exact flags, write-only simulator configuration,
catalog projection, manifest/build binding, and fixture store path.

## Adaptation boundary

Copy the `ProjectPayments/` protocol, raw-body verifier, durable inbox,
persistence contract, migrations, and entitlement-source aggregation together.
Replace `FixtureBuyerAuthenticationHandler` with the project's existing verified
principal and map only that principal's stable server-side ID. Catalog values
are deterministic simulator samples, not a pricing recommendation.
