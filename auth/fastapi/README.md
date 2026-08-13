# FastAPI: VibeNest Auth

**Status: Production-ready Auth reference.** The app uses discovery/JWKS/UserInfo,
Authorization Code + PKCE S256, one-shot state and nonce, signed
HttpOnly/Secure/SameSite session cookies, a pinned callback, and explicit ID-token
issuer, audience, signature, lifetime, and nonce validation.

## Install

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.lock
```

## Run

Copy `.env.example`, fill the values from **VibeNest Project Settings ->
Authorization**, and run:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Configure the real proxy allowlist at the ASGI server or ingress. The app never
derives its callback from forwarded host headers.

## Test

```bash
pytest -q
python -m compileall -q app tests
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
- `PORT`

## Adaptation boundary

Keep `app/vibenest_auth.py` unless the project already owns an OIDC adapter.
Adapt session persistence, error pages, route mounting, proxy configuration, and
UI. Use only the validated pairwise `sub` as the application identity. Do not add
Payments without separate user confirmation.
