# Rails: VibeNest Auth

**Status: Production-ready Auth reference.** The Rails service uses
discovery/JWKS/UserInfo, Authorization Code + PKCE S256, one-shot state and
nonce, explicit ID-token signature/issuer/audience/lifetime checks, session
rotation, Rails CSRF protection, and Secure/HttpOnly/SameSite cookies.

## Install

```bash
bundle config set path vendor/bundle
bundle install
```

## Run

Copy `.env.example`, fill values from **VibeNest Project Settings ->
Authorization**, generate a real `SECRET_KEY_BASE`, and run:

```bash
bundle exec rails server -b 0.0.0.0 -p 8080
```

Configure the trusted proxy list at Rails/ingress. Callback construction never
uses forwarded host headers.

## Test

```bash
bundle exec rails test
bundle exec rails routes
```

## Routes

- `GET /auth/vibenest/login`
- `GET /auth/vibenest/callback`
- `POST /auth/logout` (Rails CSRF required)
- `GET /api/session`
- `GET /healthz`

## Environment

- `SECRET_KEY_BASE`
- `VIBENEST_AUTH_ISSUER`
- `VIBENEST_AUTH_CLIENT_ID`
- `VIBENEST_AUTH_CLIENT_SECRET` (omit only for a registered public client)
- `VIBENEST_AUTH_REDIRECT_URI`
- `PORT`

## Adaptation boundary

Keep `app/services/vibe_nest_auth.rb` unless the project owns a maintained OIDC
adapter. Adapt controllers, session storage, errors, proxy allowlists, and UI.
Use only the validated pairwise `sub` as durable identity. Do not add Payments
without separate user confirmation.
