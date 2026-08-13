# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Email
`security@vibenest.net` with the affected example, impact, reproduction steps,
and any suggested mitigation. Do not include credentials, install codes,
session cookies, webhook signatures, personal data, or production payloads.

## Reference boundary

- The Auth examples use Authorization Code with mandatory PKCE S256 and a
  local application session. The validated pairwise `sub` is the stable user
  key; email is optional metadata.
- The Payments examples are simulator previews. They do not perform charges,
  payouts, refunds, live checkout, or production deployment.
- `.env.example` files contain placeholders only. Never commit copied Project
  Settings values, Project Payments install codes, one-time grants, access
  tokens, refresh tokens, provider keys, or webhook secrets.
- Production applications must replace demo in-memory or local-file stores
  where each example README says so, persist session/data-protection keys, and
  keep payments disabled until an explicit, separately authorized rollout.

Supported versions are the current default branch and the latest release.
