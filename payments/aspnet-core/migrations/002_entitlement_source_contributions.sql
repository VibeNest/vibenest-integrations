-- Upgrade for fixture databases created before independent paid sources were projected.
CREATE TABLE IF NOT EXISTS project_payment_entitlement_source (
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

-- An old aggregate cannot prove its provider transaction/subscription identity. Preserve it as a
-- conservative legacy contribution instead of guessing a binding or silently revoking access.
INSERT INTO project_payment_entitlement_source (
    subject_key, grant_key, source_key, provider_subscription_id, provider_transaction_id,
    quantity, status, effective_from, effective_until, billing_period_start, billing_period_end,
    source_price_id, source_event_id, last_occurred_at)
SELECT entitlement.subject_key, entitlement.grant_key,
       'legacy:' || CAST(entitlement.id AS TEXT), NULL, NULL,
       entitlement.quantity, entitlement.status, entitlement.effective_from,
       entitlement.effective_until, entitlement.billing_period_start,
       entitlement.billing_period_end, entitlement.source_price_id,
       entitlement.source_event_id, entitlement.last_occurred_at
FROM project_payment_entitlement entitlement
WHERE NOT EXISTS (
    SELECT 1 FROM project_payment_entitlement_source source
    WHERE source.subject_key = entitlement.subject_key
      AND source.grant_key = entitlement.grant_key
);

CREATE TABLE IF NOT EXISTS project_payment_refund (
    provider_transaction_id TEXT PRIMARY KEY,
    provider_subscription_id TEXT NULL,
    source_event_id TEXT NOT NULL,
    approved_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_project_payment_refund_subscription
    ON project_payment_refund (provider_subscription_id, approved_at);
