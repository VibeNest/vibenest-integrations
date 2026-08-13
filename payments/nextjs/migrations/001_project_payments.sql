-- PostgreSQL shape for a real Next.js integration. The self-contained reference fixture
-- translates the same rows to node:sqlite for native tests and disposable previews.
CREATE TABLE project_payment_webhook_event (
    id uuid PRIMARY KEY,
    destination_key text NOT NULL,
    provider_event_id text NOT NULL,
    event_type text NOT NULL,
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    body_sha256 char(64) NOT NULL,
    normalized_payload jsonb NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0,
    delivery_count integer NOT NULL DEFAULT 1,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_attempt_at timestamptz NULL,
    lease_id uuid NULL,
    lease_expires_at timestamptz NULL,
    processed_at timestamptz NULL,
    received_by_instance_id text NOT NULL,
    processed_by_instance_id text NULL,
    ignored_as_stale boolean NOT NULL DEFAULT false,
    last_error text NULL,
    dead_lettered_at timestamptz NULL,
    UNIQUE (destination_key, provider_event_id)
);
CREATE INDEX ix_project_payment_webhook_event_due
    ON project_payment_webhook_event (next_attempt_at, received_at)
    WHERE processed_at IS NULL AND dead_lettered_at IS NULL;

CREATE TABLE project_payment_customer_binding (
    provider_customer_id text PRIMARY KEY,
    subject_key text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE project_payment_entitlement (
    subject_key text NOT NULL,
    grant_key text NOT NULL,
    quantity integer NOT NULL CHECK (quantity > 0),
    status text NOT NULL CHECK (status IN ('active', 'scheduled_cancel', 'revoked', 'expired')),
    effective_from timestamptz NOT NULL,
    effective_until timestamptz NULL,
    billing_period_start timestamptz NULL,
    billing_period_end timestamptz NULL,
    source_price_key text NOT NULL,
    source_event_id text NOT NULL,
    last_occurred_at timestamptz NOT NULL,
    renewal_count integer NOT NULL DEFAULT 0,
    PRIMARY KEY (subject_key, grant_key)
);

CREATE TABLE project_payment_entitlement_source (
    subject_key text NOT NULL,
    grant_key text NOT NULL,
    source_key text NOT NULL,
    provider_subscription_id text NULL,
    provider_transaction_id text NULL,
    quantity integer NOT NULL CHECK (quantity > 0),
    status text NOT NULL CHECK (status IN ('active', 'scheduled_cancel', 'revoked', 'expired')),
    effective_from timestamptz NOT NULL,
    effective_until timestamptz NULL,
    billing_period_start timestamptz NULL,
    billing_period_end timestamptz NULL,
    source_price_key text NOT NULL,
    source_event_id text NOT NULL,
    last_occurred_at timestamptz NOT NULL,
    renewal_count integer NOT NULL DEFAULT 0,
    PRIMARY KEY (subject_key, grant_key, source_key),
    UNIQUE (grant_key, source_key)
);

CREATE TABLE project_payment_subscription (
    provider_subscription_id text PRIMARY KEY,
    subject_key text NOT NULL,
    grants_json jsonb NOT NULL,
    price_key text NOT NULL,
    status text NOT NULL,
    billing_period_start timestamptz NOT NULL,
    billing_period_end timestamptz NOT NULL,
    effective_until timestamptz NULL,
    occurred_at timestamptz NOT NULL,
    source_event_id text NOT NULL
);

CREATE TABLE project_payment_transaction (
    provider_transaction_id text PRIMARY KEY,
    subject_key text NOT NULL,
    grants_json jsonb NOT NULL,
    price_key text NOT NULL,
    price_type text NOT NULL,
    provider_subscription_id text NULL,
    amount_minor bigint NOT NULL,
    currency char(3) NOT NULL,
    billing_period_start timestamptz NULL,
    billing_period_end timestamptz NULL,
    occurred_at timestamptz NOT NULL,
    source_event_id text NOT NULL
);

CREATE TABLE project_payment_refund (
    provider_transaction_id text PRIMARY KEY,
    provider_subscription_id text NULL,
    source_event_id text NOT NULL,
    approved_at timestamptz NOT NULL
);

CREATE TABLE project_payment_evidence (
    scope_digest char(64) NOT NULL,
    name text NOT NULL,
    source_event_id text NULL,
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (scope_digest, name)
);

-- Every conditional claim and entitlement occurrence-fencing update is performed inside
-- one database transaction; the unique inbox key makes event effects idempotent.
