# Source provenance

The initial references were assembled from `VibeNest application source repository` default
branch at commit `39279c3190ac59f08354e1950ee32d59be4dd9a6` on 2026-08-13.

- Auth contract: `docs/vibenest-auth/`.
- Runnable ASP.NET Core Auth fixture: `fixtures/vibenest-auth/aspnet-core/`.
- Next.js, Express, and ASP.NET Core Payments fixtures:
  `fixtures/project-payments/`.
- Project Payments skill: `agent-skills/vibenest-project-payments/`.
- Public immutable skill descriptor: version `1.0.8`, SHA-256
  `846358045eb3cedaa95cbbeee3dd6be001bfac36f9ee21b5ab17857db2dd35e2`.
- OIDC issuer/discovery: `https://vibenest.net/` and
  `https://vibenest.net/.well-known/openid-configuration`.

The FastAPI, Laravel, and Rails adapters added on 2026-08-13 are framework-native
ports of those same pinned Auth and Project Payments contracts. They preserve
the fixture invariants for PKCE/state/nonce/callback validation, pairwise `sub`,
trusted catalog input, raw-body webhook verification, durable idempotency, and
entitlement identity. Dependency baselines at the time of the port were
FastAPI `0.141.1`, Laravel `13.25.0`, and Rails `8.1.3.1`; their generated lock
files are authoritative for reproducible installs.

The exact upstream commit is pinned by CI in `scripts/verify-repository.mjs` and
must be updated only after re-running every reference test.
