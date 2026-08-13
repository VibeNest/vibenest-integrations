# Express: VibeNest Auth

**Status: Production-ready Auth reference.** The app uses `openid-client`,
Authorization Code + PKCE S256, discovery/JWKS/UserInfo, one-shot state and
nonce, session rotation, and an HttpOnly/Secure/SameSite cookie. Callback and
redirect targets come only from `VIBENEST_AUTH_REDIRECT_URI`.

## Install

```bash
npm ci
```

## Run

Copy `.env.example`, fill values from **VibeNest Project Settings ->
Authorization**, load them into the server environment, and run:

```bash
npm start
```

The sample uses the default in-memory `express-session` store only to stay
self-contained. Replace it with the project's PostgreSQL or Redis session store
before production. Set `TRUSTED_PROXY_CIDR` to the actual proxy network; do not
trust arbitrary forwarded headers or the whole internet.

## Test

```bash
npm test
npm run build
```

## Routes

- `GET /auth/vibenest/login`
- `GET /auth/vibenest/callback`
- `POST /auth/logout` (same-origin CSRF required)
- `GET /api/session`
- `GET /healthz`

## Environment

- `VIBENEST_AUTH_ISSUER`
- `VIBENEST_AUTH_CLIENT_ID`
- `VIBENEST_AUTH_CLIENT_SECRET` (omit only for a registered public client)
- `VIBENEST_AUTH_REDIRECT_URI`
- `APP_SESSION_SECRET`
- `TRUSTED_PROXY_CIDR`
- `PORT`

## Adaptation boundary

Keep `src/vibenest-auth.mjs` unless the project already has a maintained OIDC
adapter. Adapt the session store, error pages, route mounting, and UI. Protected
routes use only `request.session.user.subject`, the validated pairwise `sub`.
Never accept browser-authored user IDs and do not add Payments without separate
user confirmation.
