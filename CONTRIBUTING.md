# Contributing

Keep each example small, runnable, and independently testable. Changes to Auth
or Project Payments contracts must start from the current VibeNest production
implementation or immutable skill bundle, not from memory.

1. Create a feature branch.
2. Change the smallest applicable example.
3. Update its README and `.env.example` when routes or configuration change.
4. Run `npm ci && npm test` in the repository root, then the example's own
   install/build/test commands.
5. Run a secret scan before pushing.
6. Open a pull request describing contract changes and their source.

Do not auto-merge dependency updates that change OIDC validation, session
handling, webhook verification, durable inbox behavior, catalog parsing, or
entitlement aggregation. Those changes require the full fixture test suite.

Roadmap proposals for FastAPI, Laravel, Rails, and other stacks are welcome as
issues. Please do not add an unverified implementation merely to expand the
matrix.
