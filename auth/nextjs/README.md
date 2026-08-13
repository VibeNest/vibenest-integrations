# Next.js App Router: VibeNest Auth

**Status: Production-ready Auth reference.** This app uses `openid-client` with
Authorization Code, mandatory PKCE S256, discovery/JWKS/UserInfo, state, nonce,
and a server-only encrypted application session. The configured callback URI is
the only trusted origin/path; incoming Host and forwarded headers cannot change
it.

## Install

```bash
npm ci
```

## Run

Copy `.env.example` to `.env.local`, fill values from **VibeNest Project
Settings -> Authorization**, use HTTPS, then run:

```bash
npm run dev
```

## Test

```bash
npm test
npm run build
```

## Routes

- `GET /auth/vibenest/login` - starts Code + S256 PKCE.
- `GET /auth/vibenest/callback` - validates code, state, nonce, issuer,
  audience, signature, lifetime, and PKCE.
- `POST /auth/logout` - requires same-origin CSRF header and clears the local
  session.
- `GET /api/session` - returns the validated pairwise `sub` and optional email
  metadata.

## Environment

- `VIBENEST_AUTH_ISSUER`
- `VIBENEST_AUTH_CLIENT_ID`
- `VIBENEST_AUTH_CLIENT_SECRET` (omit only for a registered public client)
- `VIBENEST_AUTH_REDIRECT_URI`
- `APP_SESSION_SECRET` (at least 32 random characters)

## Adaptation boundary

Copy `lib/vibenest-auth.js` unchanged unless the project's maintained OIDC
library already owns this boundary. Adapt `lib/session.js` to the project's
session store and key management. Adapt Route Handlers and UI paths to existing
routing. Every paid or protected route must read `session.subject`; never accept
an authoritative user ID from browser input. Do not add any Payments artifact
without separate user confirmation.
