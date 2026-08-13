-- Reference fixture migration. Production adapters should express the same rows through
-- their application's normal EF Core migration pipeline.
CREATE TABLE project_payment_webhook_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination_key TEXT NOT NULL,
    provider_event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    body_sha256 TEXT NOT NULL,
    normalized_payload TEXT NOT NULL,
    next_attempt_at TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    delivery_count INTEGER NOT NULL DEFAULT 1,
    lease_id TEXT NULL,
    lease_expires_at TEXT NULL,
    received_by_instance_id TEXT NOT NULL,
    processed_by_instance_id TEXT NULL,
    processed_at TEXT NULL,
    dead_lettered_at TEXT NULL,
    ignored_as_stale INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NULL,
    UNIQUE (destination_key, provider_event_id)
);
CREATE INDEX ix_project_payment_webhook_event_due
    ON project_payment_webhook_event (next_attempt_at, received_at)
    WHERE processed_at IS NULL AND dead_lettered_at IS NULL;

CREATE TABLE project_payment_customer_binding (
    provider_customer_id TEXT PRIMARY KEY,
    subject_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE project_payment_entitlement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_key TEXT NOT NULL,
    grant_key TEXT NOT NULL,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'scheduled_cancel', 'revoked', 'expired')),
    effective_from TEXT NOT NULL,
    effective_until TEXT NULL,
    billing_period_start TEXT NULL,
    billing_period_end TEXT NULL,
    source_price_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    last_occurred_at TEXT NOT NULL,
    UNIQUE (subject_key, grant_key)
);

CREATE TABLE project_payment_entitlement_source (
    subject_key TEXT NOT NULL,
    grant_key TEXT NOT NULL,
    source_key TEXT NOT NULL,
    provider_subscription_id TEXT NULL,
    provider_transaction_id TEXT NULL,
    quantity INTEGER NOT NULL CHECK (quantity > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'scheduled_cancel', 'revoked', 'expired')),
    effective_from TEXT NOT NULL,
    effective_until TEXT NULL,
    billing_period_start TEXT NULL,
    billing_period_end TEXT NULL,
    source_price_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    last_occurred_at TEXT NOT NULL,
    PRIMARY KEY (subject_key, grant_key, source_key),
    UNIQUE (grant_key, source_key)
);

CREATE TABLE project_payment_transaction (
    provider_transaction_id TEXT PRIMARY KEY,
    subject_key TEXT NOT NULL,
    subscription_id TEXT NULL,
    product_id TEXT NOT NULL,
    price_id TEXT NOT NULL,
    amount_minor INTEGER NOT NULL,
    currency TEXT NOT NULL,
    period_start TEXT NULL,
    period_end TEXT NULL,
    occurred_at TEXT NOT NULL
);

CREATE TABLE project_payment_subscription (
    provider_subscription_id TEXT PRIMARY KEY,
    subject_key TEXT NOT NULL,
    product_id TEXT NOT NULL,
    price_id TEXT NOT NULL,
    status TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    scheduled_change_at TEXT NULL,
    last_occurred_at TEXT NOT NULL
);

CREATE TABLE project_payment_refund (
    provider_transaction_id TEXT PRIMARY KEY,
    provider_subscription_id TEXT NULL,
    source_event_id TEXT NOT NULL,
    approved_at TEXT NOT NULL
);
CREATE INDEX ix_project_payment_refund_subscription
    ON project_payment_refund (provider_subscription_id, approved_at);

CREATE TABLE project_payment_evidence (
    scope_digest TEXT NOT NULL,
    name TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (scope_digest, name)
);

-- Every source contribution, derived entitlement aggregate, refund projection, and processed_at
-- marker is committed in one SQLite transaction. Per-source last_occurred_at fencing prevents
-- stale delivery from replacing a newer contribution without coupling independent purchases.
