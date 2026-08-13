# ASP.NET Core: VibeNest Auth

**Status: Production-ready Auth reference.** The maintained ASP.NET Core OIDC
handler performs Authorization Code + PKCE S256 and validates discovery/JWKS,
issuer, audience, signature, lifetime, correlation state, nonce, and UserInfo.
The application creates its own HttpOnly/Secure/SameSite cookie and never saves
OAuth tokens into it.

## Install

```bash
dotnet restore --locked-mode
```

## Run

Set values from **VibeNest Project Settings -> Authorization** using server
environment variables, then run:

```bash
dotnet run --project VibeNestAuth.ReferenceApp.csproj
```

For a long-lived app, persist ASP.NET Core Data Protection keys in a mounted
volume or external key store so local sessions survive container replacement.

## Test

```bash
dotnet test tests/VibeNestAuth.ReferenceApp.Tests.csproj
dotnet build -c Release --no-restore
```

## Routes

- `GET /auth/vibenest/login`
- `GET /auth/vibenest/callback`
- `POST /auth/logout` (authenticated antiforgery request)
- `GET /api/session`
- `GET /healthz`

## Environment

- `VIBENEST_AUTH_ENABLED`
- `VIBENEST_AUTH_ISSUER`
- `VIBENEST_AUTH_CLIENT_ID`
- `VIBENEST_AUTH_CLIENT_SECRET`
- `VIBENEST_AUTH_REDIRECT_URI`

## Adaptation boundary

The OIDC and cookie options can normally be copied unchanged. Adapt route/UI
names and Data Protection persistence. Connect protected application routes to
the authenticated principal's pairwise `sub`; email is optional metadata, not
a permanent ID. The confidential client secret remains server-side. Do not add
Payments without separate user confirmation.
