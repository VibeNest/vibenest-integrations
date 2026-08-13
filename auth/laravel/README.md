# Laravel: VibeNest Auth

**Status: Production-ready Auth reference.** The Laravel service uses OIDC
discovery/JWKS/UserInfo, Authorization Code + PKCE S256, one-shot state and
nonce, ID-token validation, session invalidation, and encrypted
HttpOnly/Secure/SameSite cookies. The callback is always the configured URI.

## Install

```bash
composer install
```

## Run

Copy `.env.example`, fill values from **VibeNest Project Settings ->
Authorization**, generate a real `APP_KEY`, and run:

```bash
php artisan serve --host=0.0.0.0 --port=8080
```

Use the project's durable Laravel session driver in production. Configure
trusted proxies explicitly at the ingress; never derive the callback from a
forwarded host.

## Test

```bash
composer test
php artisan route:list
```

## Routes

- `GET /auth/vibenest/login`
- `GET /auth/vibenest/callback`
- `POST /auth/logout` (Laravel CSRF middleware)
- `GET /api/session`
- `GET /healthz`

## Environment

- `APP_KEY`
- `SESSION_DRIVER`
- `SESSION_SECURE_COOKIE`
- `VIBENEST_AUTH_ISSUER`
- `VIBENEST_AUTH_CLIENT_ID`
- `VIBENEST_AUTH_CLIENT_SECRET` (omit only for a registered public client)
- `VIBENEST_AUTH_REDIRECT_URI`
- `PORT`

## Adaptation boundary

Keep `app/Services/VibeNestAuth.php` unless the application already has a
maintained OIDC adapter. Adapt routes, error pages, session storage, proxy
allowlists, and UI. Use only the validated pairwise `sub` as the durable user
key. Do not add Payments without separate user confirmation.
