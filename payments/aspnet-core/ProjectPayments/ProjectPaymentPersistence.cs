using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Fixture.ProjectPayments;

public sealed record NormalizedProjectPaymentEvent(
    string DestinationKey,
    string EventId,
    string EventType,
    DateTimeOffset OccurredAt,
    string BodyDigest,
    string EvidenceScope,
    string? SubjectKey,
    string? CustomerId,
    string? TransactionId,
    string? SubscriptionId,
    string? ProductId,
    string? PriceId,
    string Status,
    long? AmountMinor,
    string? Currency,
    DateTimeOffset? BillingPeriodStart,
    DateTimeOffset? BillingPeriodEnd,
    DateTimeOffset? ScheduledChangeAt);

public sealed record ProjectPaymentInboxSnapshot(
    string EventId,
    string EventType,
    int DeliveryCount,
    int AttemptCount,
    bool Processed,
    bool IgnoredAsStale,
    bool DeadLettered);

public sealed record ProjectPaymentEntitlementSnapshot(
    string SubjectKey,
    string GrantKey,
    int Quantity,
    string Status,
    string SourceEventId,
    DateTimeOffset LastOccurredAt,
    DateTimeOffset? EffectiveUntil);

public sealed record ProjectPaymentEntitlementSourceSnapshot(
    string SubjectKey,
    string GrantKey,
    string SourceKey,
    string? SubscriptionId,
    string? TransactionId,
    int Quantity,
    string Status,
    string SourceEventId,
    DateTimeOffset LastOccurredAt,
    DateTimeOffset? EffectiveUntil);

public sealed record ProjectPaymentRefundSnapshot(
    string TransactionId,
    string? SubscriptionId,
    string SourceEventId,
    DateTimeOffset ApprovedAt);

public sealed record ProjectPaymentStoreSnapshot(
    IReadOnlyList<ProjectPaymentInboxSnapshot> Events,
    IReadOnlyDictionary<string, ProjectPaymentEntitlementSnapshot> Entitlements,
    IReadOnlyList<ProjectPaymentEntitlementSourceSnapshot> EntitlementSources,
    IReadOnlyList<ProjectPaymentRefundSnapshot> Refunds,
    IReadOnlySet<string> Evidence,
    bool RestartReplayObserved);

public sealed class DurableProjectPaymentStore
{
    private const int MaximumAttempts = 10;
    private const string RestartReplayProbeEventType = "vibenest.restart_replay_probe";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly IReadOnlySet<string> RequiredEvidence = new HashSet<string>(StringComparer.Ordinal)
    {
        "price-preview", "one-time-purchase", "subscription-purchase", "declined-checkout",
        "duplicate-delivery", "out-of-order-delivery", "renewal", "scheduled-cancellation",
        "immediate-refund", "customer-portal"
    };

    private readonly string _connectionString;
    private readonly ProjectPaymentCatalog _catalog;
    private readonly TimeProvider _timeProvider;
    private readonly string _instanceId;
    private readonly string _evidenceScope;

    public DurableProjectPaymentStore(
        string path,
        ProjectPaymentCatalog catalog,
        string evidenceScope,
        TimeProvider? timeProvider = null,
        string? instanceId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        if (evidenceScope.Length != 64 || evidenceScope.Any(value => value is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new ArgumentException("A lowercase SHA-256 lifecycle evidence scope is required.", nameof(evidenceScope));
        _evidenceScope = evidenceScope;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _instanceId = instanceId ?? Guid.NewGuid().ToString("N");
        ProjectPaymentSecurity.RequireIdentifier(_instanceId, "Store instance id");
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = fullPath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = false,
            DefaultTimeout = 5
        }.ToString();
        Initialize();
    }

    public string EvidenceScope => _evidenceScope;

    public async Task BindCustomerAsync(string providerCustomerId, string subjectKey, CancellationToken cancellationToken = default)
    {
        ProjectPaymentSecurity.RequireIdentifier(providerCustomerId, "Provider customer id");
        ProjectPaymentSecurity.RequireIdentifier(subjectKey, "Authenticated subject");
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var existing = await ScalarTextAsync(connection, transaction,
            "SELECT subject_key FROM project_payment_customer_binding WHERE provider_customer_id = $customer;",
            ("$customer", providerCustomerId), cancellationToken);
        var reverse = await ScalarTextAsync(connection, transaction,
            "SELECT provider_customer_id FROM project_payment_customer_binding WHERE subject_key = $subject;",
            ("$subject", subjectKey), cancellationToken);
        if ((existing is not null && existing != subjectKey) || (reverse is not null && reverse != providerCustomerId))
            throw new InvalidOperationException("A provider customer binding cannot be reassigned.");
        await ExecuteAsync(connection, transaction,
            "INSERT INTO project_payment_customer_binding(provider_customer_id, subject_key, created_at) VALUES ($customer, $subject, $now) ON CONFLICT(provider_customer_id) DO NOTHING;",
            [("$customer", providerCustomerId), ("$subject", subjectKey), ("$now", Format(_timeProvider.GetUtcNow()))], cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<string?> ResolveSubjectAsync(string providerCustomerId, CancellationToken cancellationToken = default)
    {
        ProjectPaymentSecurity.RequireIdentifier(providerCustomerId, "Provider customer id");
        await using var connection = await OpenAsync(cancellationToken);
        return await ScalarTextAsync(connection, null,
            "SELECT subject_key FROM project_payment_customer_binding WHERE provider_customer_id = $customer;",
            ("$customer", providerCustomerId), cancellationToken);
    }

    public async Task<bool> InsertVerifiedEventAsync(NormalizedProjectPaymentEvent paymentEvent, CancellationToken cancellationToken = default)
    {
        ValidateNormalizedEvent(paymentEvent);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var now = Format(_timeProvider.GetUtcNow());
        var inserted = await ExecuteAsync(connection, transaction, """
            INSERT INTO project_payment_webhook_event(
                destination_key, provider_event_id, event_type, occurred_at, received_at,
                body_sha256, normalized_payload, next_attempt_at, received_by_instance_id)
            VALUES ($destination, $event, $type, $occurred, $received, $digest, $payload, $received, $instance)
            ON CONFLICT(destination_key, provider_event_id) DO NOTHING;
            """,
            [
                ("$destination", paymentEvent.DestinationKey), ("$event", paymentEvent.EventId),
                ("$type", paymentEvent.EventType), ("$occurred", Format(paymentEvent.OccurredAt)),
                ("$received", now), ("$digest", paymentEvent.BodyDigest),
                ("$payload", JsonSerializer.Serialize(paymentEvent, JsonOptions)), ("$instance", _instanceId)
            ], cancellationToken);
        if (inserted == 1)
        {
            await transaction.CommitAsync(cancellationToken);
            return true;
        }

        await using var duplicate = connection.CreateCommand();
        duplicate.Transaction = transaction;
        duplicate.CommandText = "SELECT body_sha256 FROM project_payment_webhook_event WHERE destination_key = $destination AND provider_event_id = $event;";
        duplicate.Parameters.AddWithValue("$destination", paymentEvent.DestinationKey);
        duplicate.Parameters.AddWithValue("$event", paymentEvent.EventId);
        var existingDigest = (string?)await duplicate.ExecuteScalarAsync(cancellationToken);
        if (existingDigest is null || !ProjectPaymentSecurity.ConstantText(existingDigest, paymentEvent.BodyDigest))
            throw new InvalidSimulatorEventException("A provider event id was reused with different signed bytes.");
        await ExecuteAsync(connection, transaction,
            "UPDATE project_payment_webhook_event SET delivery_count = delivery_count + 1 WHERE destination_key = $destination AND provider_event_id = $event;",
            [("$destination", paymentEvent.DestinationKey), ("$event", paymentEvent.EventId)], cancellationToken);
        await InsertEvidenceAsync(connection, transaction, paymentEvent.EvidenceScope, "duplicate-delivery", cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return false;
    }

    public async Task StageRestartReplayProbeAsync(string destinationKey, CancellationToken cancellationToken = default)
    {
        ProjectPaymentSecurity.RequireIdentifier(destinationKey, "Restart replay destination");
        if (!ProjectPaymentSecurity.ConstantText(destinationKey, _catalog.EnvironmentExternalId))
            throw new InvalidOperationException("The restart replay probe targets another simulator environment.");
        var now = _timeProvider.GetUtcNow();
        var eventId = $"vn_restart_probe_{ProjectPaymentSecurity.StableId(destinationKey, _evidenceScope, _instanceId)}";
        var bodyDigest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            $"restart-replay\0{destinationKey}\0{_evidenceScope}\0{_instanceId}")));
        var paymentEvent = new NormalizedProjectPaymentEvent(
            destinationKey,
            eventId,
            RestartReplayProbeEventType,
            now,
            bodyDigest,
            _evidenceScope,
            null,
            null,
            null,
            null,
            null,
            null,
            "probe",
            null,
            null,
            null,
            null,
            null);
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        var stagedAt = Format(now);
        await ExecuteAsync(connection, transaction, """
            INSERT INTO project_payment_webhook_event(
                destination_key, provider_event_id, event_type, occurred_at, received_at,
                body_sha256, normalized_payload, next_attempt_at, received_by_instance_id)
            VALUES ($destination, $event, $type, $occurred, $received, $digest, $payload, $received, $instance)
            ON CONFLICT(destination_key, provider_event_id) DO NOTHING;
            """,
            [
                ("$destination", destinationKey), ("$event", eventId),
                ("$type", RestartReplayProbeEventType), ("$occurred", stagedAt),
                ("$received", stagedAt), ("$digest", bodyDigest),
                ("$payload", JsonSerializer.Serialize(paymentEvent, JsonOptions)), ("$instance", _instanceId)
            ], cancellationToken);
        await transaction.CommitAsync(cancellationToken);
    }

    public async Task<int> ProcessDueAsync(CancellationToken cancellationToken = default)
    {
        var now = _timeProvider.GetUtcNow();
        var leaseId = Guid.NewGuid().ToString("N");
        var ids = new List<long>();
        await using (var connection = await OpenAsync(cancellationToken))
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                UPDATE project_payment_webhook_event
                SET lease_id = $lease, lease_expires_at = $expires
                WHERE id IN (
                    SELECT id FROM project_payment_webhook_event
                    WHERE processed_at IS NULL AND dead_lettered_at IS NULL AND next_attempt_at <= $now
                      AND (lease_id IS NULL OR lease_expires_at <= $now)
                      AND (event_type <> $probe OR received_by_instance_id <> $instance)
                    ORDER BY received_at, id LIMIT 32
                )
                RETURNING id;
                """;
            command.Parameters.AddWithValue("$lease", leaseId);
            command.Parameters.AddWithValue("$expires", Format(now.AddMinutes(2)));
            command.Parameters.AddWithValue("$now", Format(now));
            command.Parameters.AddWithValue("$probe", RestartReplayProbeEventType);
            command.Parameters.AddWithValue("$instance", _instanceId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) ids.Add(reader.GetInt64(0));
        }

        var processed = 0;
        foreach (var id in ids)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (await ApplyClaimAsync(id, leaseId, cancellationToken)) processed++;
        }
        return processed;
    }

    internal async Task RecordProviderEvidenceAsync(string evidence, CancellationToken cancellationToken = default)
    {
        if (evidence is not ("price-preview" or "customer-portal"))
            throw new InvalidOperationException("Only a trusted provider operation can record this lifecycle evidence.");
        await using var connection = await OpenAsync(cancellationToken);
        await InsertEvidenceAsync(connection, null, _evidenceScope, evidence, cancellationToken);
    }

    public async Task<bool> HasEntitlementAsync(string subjectKey, string grantKey, CancellationToken cancellationToken = default)
    {
        ProjectPaymentSecurity.RequireIdentifier(subjectKey, "Authenticated subject");
        ProjectPaymentSecurity.RequireIdentifier(grantKey, "Entitlement key");
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT status, effective_until FROM project_payment_entitlement
            WHERE subject_key = $subject AND grant_key = $grant;
            """;
        command.Parameters.AddWithValue("$subject", subjectKey);
        command.Parameters.AddWithValue("$grant", grantKey);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return false;
        var status = reader.GetString(0);
        if (status is not ("active" or "scheduled_cancel")) return false;
        return reader.IsDBNull(1) || Parse(reader.GetString(1)) > _timeProvider.GetUtcNow();
    }

    public async Task<ProjectPaymentVerificationStatus> VerificationStatusAsync(string evidenceScope, CancellationToken cancellationToken = default)
    {
        if (!ProjectPaymentSecurity.ConstantText(evidenceScope, _evidenceScope)) return new(false, false, false);
        await using var connection = await OpenAsync(cancellationToken);
        var evidence = new HashSet<string>(StringComparer.Ordinal);
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT name FROM project_payment_evidence WHERE scope_digest=$scope;";
            command.Parameters.AddWithValue("$scope", evidenceScope);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) evidence.Add(reader.GetString(0));
        }
        var total = await ScalarLongAsync(connection, "SELECT COUNT(*) FROM project_payment_webhook_event;", cancellationToken);
        var unfinished = await ScalarLongAsync(connection,
            "SELECT COUNT(*) FROM project_payment_webhook_event WHERE processed_at IS NULL OR dead_lettered_at IS NOT NULL;", cancellationToken);
        return new(RequiredEvidence.All(evidence.Contains), total > 0 && unfinished == 0, evidence.Contains("restart-replay"));
    }

    public async Task<ProjectPaymentStoreSnapshot> SnapshotAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken);
        var events = new List<ProjectPaymentInboxSnapshot>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT provider_event_id,event_type,delivery_count,attempt_count,processed_at,ignored_as_stale,dead_lettered_at FROM project_payment_webhook_event ORDER BY id;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                events.Add(new(reader.GetString(0), reader.GetString(1), reader.GetInt32(2), reader.GetInt32(3), !reader.IsDBNull(4), reader.GetInt64(5) != 0, !reader.IsDBNull(6)));
        }
        var entitlements = new Dictionary<string, ProjectPaymentEntitlementSnapshot>(StringComparer.Ordinal);
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT subject_key,grant_key,quantity,status,source_event_id,last_occurred_at,effective_until FROM project_payment_entitlement;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                var item = new ProjectPaymentEntitlementSnapshot(reader.GetString(0), reader.GetString(1), reader.GetInt32(2), reader.GetString(3), reader.GetString(4), Parse(reader.GetString(5)), reader.IsDBNull(6) ? null : Parse(reader.GetString(6)));
                entitlements[$"{item.SubjectKey}:{item.GrantKey}"] = item;
            }
        }
        var entitlementSources = new List<ProjectPaymentEntitlementSourceSnapshot>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                SELECT subject_key,grant_key,source_key,provider_subscription_id,provider_transaction_id,
                       quantity,status,source_event_id,last_occurred_at,effective_until
                FROM project_payment_entitlement_source ORDER BY subject_key,grant_key,source_key;
                """;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                entitlementSources.Add(new(
                    reader.GetString(0), reader.GetString(1), reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.GetInt32(5), reader.GetString(6), reader.GetString(7), Parse(reader.GetString(8)),
                    reader.IsDBNull(9) ? null : Parse(reader.GetString(9))));
        }
        var refunds = new List<ProjectPaymentRefundSnapshot>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT provider_transaction_id,provider_subscription_id,source_event_id,approved_at FROM project_payment_refund ORDER BY approved_at,provider_transaction_id;";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                refunds.Add(new(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.GetString(2), Parse(reader.GetString(3))));
        }
        var evidence = new HashSet<string>(StringComparer.Ordinal);
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT name FROM project_payment_evidence WHERE scope_digest=$scope;";
            command.Parameters.AddWithValue("$scope", _evidenceScope);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken)) evidence.Add(reader.GetString(0));
        }
        return new(events, entitlements, entitlementSources, refunds, evidence, evidence.Contains("restart-replay"));
    }

    private async Task<bool> ApplyClaimAsync(long id, string leaseId, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var transaction = connection.BeginTransaction();
        string? serialized = null;
        string? receivedBy = null;
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT normalized_payload,received_by_instance_id FROM project_payment_webhook_event WHERE id=$id AND lease_id=$lease AND processed_at IS NULL AND dead_lettered_at IS NULL;";
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$lease", leaseId);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            if (await reader.ReadAsync(cancellationToken))
            {
                serialized = reader.GetString(0);
                receivedBy = reader.GetString(1);
            }
        }
        if (serialized is null)
        {
            await transaction.RollbackAsync(cancellationToken);
            return false;
        }

        try
        {
            var paymentEvent = JsonSerializer.Deserialize<NormalizedProjectPaymentEvent>(serialized, JsonOptions)
                ?? throw new InvalidOperationException("The durable normalized event is invalid.");
            ValidatePersistedEvidenceScope(paymentEvent);
            var stale = await ApplyEventAsync(connection, transaction, paymentEvent, cancellationToken);
            if (stale) await InsertEvidenceAsync(connection, transaction, paymentEvent.EvidenceScope, "out-of-order-delivery", cancellationToken);
            if (receivedBy != _instanceId)
                await InsertEvidenceAsync(connection, transaction, paymentEvent.EvidenceScope, "restart-replay", cancellationToken);
            await ExecuteAsync(connection, transaction, """
                UPDATE project_payment_webhook_event
                SET processed_at=$now, processed_by_instance_id=$instance, ignored_as_stale=$stale,
                    lease_id=NULL, lease_expires_at=NULL, last_error=NULL
                WHERE id=$id AND lease_id=$lease;
                """,
                [("$now", Format(_timeProvider.GetUtcNow())), ("$instance", _instanceId), ("$stale", stale ? 1 : 0), ("$id", id), ("$lease", leaseId)], cancellationToken);
            await transaction.CommitAsync(cancellationToken);
            return true;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            await transaction.RollbackAsync(cancellationToken);
            await RecordFailureAsync(id, leaseId, exception, cancellationToken);
            return false;
        }
    }

    private async Task<bool> ApplyEventAsync(SqliteConnection connection, SqliteTransaction transaction, NormalizedProjectPaymentEvent item, CancellationToken cancellationToken)
    {
        switch (item.EventType)
        {
            case RestartReplayProbeEventType:
                return false;

            case "transaction.payment_failed":
                await InsertEvidenceAsync(connection, transaction, item.EvidenceScope, "declined-checkout", cancellationToken);
                return false;

            case "transaction.completed":
                {
                    var price = _catalog.ResolveByExternalIds(item.ProductId!, item.PriceId!);
                    if (await IsTransactionFencedByRefundAsync(connection, transaction, item, cancellationToken)) return true;
                    if (price.Type == "recurring" && item.SubscriptionId is not null)
                    {
                        var subscription = await ReadSubscriptionAsync(connection, transaction, item.SubscriptionId, cancellationToken);
                        if (subscription is not null)
                        {
                            EnsureSameSubscriptionTarget(subscription, item);
                            if (item.BillingPeriodEnd < subscription.End) return true;
                            if (subscription.Status != "active")
                            {
                                if (item.OccurredAt <= subscription.LastOccurredAt) return true;
                                throw new InvalidSimulatorEventException("A recurring transaction cannot reactivate a scheduled or revoked subscription source.");
                            }
                            if (item.BillingPeriodEnd > subscription.End
                                && item.BillingPeriodStart != subscription.End)
                                throw new InvalidSimulatorEventException("A recurring transaction cannot discontinuously advance a subscription.");
                        }
                        else
                        {
                            var priorTransaction = await ReadFirstTransactionForSubscriptionAsync(connection, transaction, item.SubscriptionId, cancellationToken);
                            if (priorTransaction is not null) EnsureSameTransactionSubscriptionTarget(priorTransaction, item);
                        }
                    }
                    var transactionInserted = await ExecuteAsync(connection, transaction, """
                    INSERT INTO project_payment_transaction(provider_transaction_id,subject_key,subscription_id,product_id,price_id,amount_minor,currency,period_start,period_end,occurred_at)
                    VALUES($transaction,$subject,$subscription,$product,$price,$amount,$currency,$start,$end,$occurred)
                    ON CONFLICT(provider_transaction_id) DO NOTHING;
                    """,
                        [("$transaction", item.TransactionId!), ("$subject", item.SubjectKey!), ("$subscription", item.SubscriptionId),
                     ("$product", item.ProductId!), ("$price", item.PriceId!), ("$amount", item.AmountMinor!.Value), ("$currency", item.Currency!),
                     ("$start", item.BillingPeriodStart is null ? null : Format(item.BillingPeriodStart.Value)),
                     ("$end", item.BillingPeriodEnd is null ? null : Format(item.BillingPeriodEnd.Value)), ("$occurred", Format(item.OccurredAt))], cancellationToken);
                    if (transactionInserted == 0)
                    {
                        var existing = await ReadTransactionAsync(connection, transaction, item.TransactionId!, cancellationToken)
                            ?? throw new InvalidSimulatorEventException("The transaction projection disappeared during idempotency validation.");
                        if (existing.Subject != item.SubjectKey || existing.SubscriptionId != item.SubscriptionId
                            || existing.ProductId != item.ProductId || existing.PriceId != item.PriceId
                            || existing.AmountMinor != item.AmountMinor || existing.Currency != item.Currency
                            || existing.PeriodStart != item.BillingPeriodStart || existing.PeriodEnd != item.BillingPeriodEnd)
                            throw new InvalidSimulatorEventException("A transaction id cannot be rebound to a different buyer, subscription, or trusted catalog price.");
                        return true;
                    }
                    var stale = await ApplyGrantsAsync(connection, transaction, item, price, "active", item.BillingPeriodEnd, cancellationToken);
                    if (price.Type == "one_time") await InsertEvidenceAsync(connection, transaction, item.EvidenceScope, "one-time-purchase", cancellationToken);
                    return stale;
                }

            case "subscription.created":
            case "subscription.updated":
            case "subscription.canceled":
                {
                    var price = _catalog.ResolveByExternalIds(item.ProductId!, item.PriceId!);
                    if (item.EventType != "subscription.canceled"
                        && await IsSubscriptionFencedByRefundAsync(connection, transaction, item, cancellationToken))
                        return true;
                    var previous = await ReadSubscriptionAsync(connection, transaction, item.SubscriptionId!, cancellationToken);
                    if (item.EventType == "subscription.created" && previous is not null) return true;
                    if (item.EventType == "subscription.created" && previous is null)
                    {
                        var priorTransaction = await ReadFirstTransactionForSubscriptionAsync(connection, transaction, item.SubscriptionId!, cancellationToken);
                        if (priorTransaction is not null) EnsureSameTransactionSubscriptionTarget(priorTransaction, item);
                    }
                    if (item.EventType != "subscription.created" && previous is null)
                        throw new RetryableProjectPaymentDependencyException("The prior signed subscription period is not processed yet.");
                    if (previous is not null) EnsureSameSubscriptionTarget(previous, item);

                    if (previous is not null && item.EventType == "subscription.updated" && item.ScheduledChangeAt is null)
                    {
                        if (previous.Status != "active")
                            throw new InvalidSimulatorEventException("A renewal cannot advance a non-active subscription.");
                        if (item.BillingPeriodStart != previous.End || item.BillingPeriodEnd != PeriodEnd(previous.End, price.Interval!))
                            throw new InvalidSimulatorEventException("A renewal did not advance the prior signed billing period exactly once.");
                    }
                    if (previous is not null && item.EventType == "subscription.updated" && item.ScheduledChangeAt is not null)
                    {
                        if (previous.Status != "active" || item.BillingPeriodStart != previous.Start || item.BillingPeriodEnd != previous.End)
                            throw new InvalidSimulatorEventException("A scheduled cancellation requires and must reuse the active authoritative billing period.");
                    }
                    if (previous is not null && item.EventType == "subscription.canceled"
                        && (previous.Status is not ("active" or "scheduled_cancel")
                            || item.BillingPeriodStart != previous.Start || item.BillingPeriodEnd != previous.End))
                        throw new InvalidSimulatorEventException("An immediate cancellation must reuse an active authoritative billing period.");

                    var entitlementStatus = item.EventType == "subscription.canceled" ? "revoked"
                        : item.ScheduledChangeAt is not null ? "scheduled_cancel" : "active";

                    await ExecuteAsync(connection, transaction, """
                    INSERT INTO project_payment_subscription(provider_subscription_id,subject_key,product_id,price_id,status,period_start,period_end,scheduled_change_at,last_occurred_at)
                    VALUES($subscription,$subject,$product,$price,$status,$start,$end,$scheduled,$occurred)
                    ON CONFLICT(provider_subscription_id) DO UPDATE SET
                      subject_key=excluded.subject_key,product_id=excluded.product_id,price_id=excluded.price_id,status=excluded.status,
                      period_start=excluded.period_start,period_end=excluded.period_end,scheduled_change_at=excluded.scheduled_change_at,last_occurred_at=excluded.last_occurred_at
                    WHERE excluded.last_occurred_at > project_payment_subscription.last_occurred_at;
                    """,
                        [("$subscription", item.SubscriptionId!), ("$subject", item.SubjectKey!), ("$product", item.ProductId!),
                     ("$price", item.PriceId!), ("$status", entitlementStatus), ("$start", Format(item.BillingPeriodStart!.Value)),
                     ("$end", Format(item.BillingPeriodEnd!.Value)), ("$scheduled", item.ScheduledChangeAt is null ? null : Format(item.ScheduledChangeAt.Value)),
                     ("$occurred", Format(item.OccurredAt))], cancellationToken);
                    var effectiveUntil = item.EventType == "subscription.canceled" ? item.OccurredAt : item.BillingPeriodEnd;
                    var stale = await ApplyGrantsAsync(connection, transaction, item, price, entitlementStatus, effectiveUntil, cancellationToken);
                    if (item.EventType == "subscription.canceled")
                        await RecordImmediateRefundIfCompleteAsync(connection, transaction, item.SubscriptionId!, item.EvidenceScope, cancellationToken);
                    if (!stale)
                    {
                        if (item.EventType == "subscription.created") await InsertEvidenceAsync(connection, transaction, item.EvidenceScope, "subscription-purchase", cancellationToken);
                        else if (item.EventType == "subscription.updated" && item.ScheduledChangeAt is null) await InsertEvidenceAsync(connection, transaction, item.EvidenceScope, "renewal", cancellationToken);
                        else if (item.EventType == "subscription.updated") await InsertEvidenceAsync(connection, transaction, item.EvidenceScope, "scheduled-cancellation", cancellationToken);
                    }
                    return stale;
                }

            case "adjustment.created":
                return false;

            case "adjustment.updated":
                {
                    if (item.Status != "approved") return false;
                    var transactionProjection = await ReadTransactionAsync(connection, transaction, item.TransactionId!, cancellationToken)
                        ?? throw new RetryableProjectPaymentDependencyException("The referenced transaction is not processed yet.");
                    var price = _catalog.ResolveByExternalIds(transactionProjection.ProductId, transactionProjection.PriceId);
                    if (item.AmountMinor != transactionProjection.AmountMinor || item.Currency != transactionProjection.Currency)
                        throw new InvalidSimulatorEventException("The approved refund totals do not match the referenced trusted transaction price.");
                    if (item.OccurredAt < transactionProjection.OccurredAt)
                        throw new InvalidSimulatorEventException("An approved refund cannot precede its trusted transaction.");
                    if (!await InsertRefundProjectionAsync(connection, transaction, item, transactionProjection.SubscriptionId, cancellationToken))
                        return true;
                    var adjusted = item with
                    {
                        SubjectKey = transactionProjection.Subject,
                        SubscriptionId = transactionProjection.SubscriptionId,
                        ProductId = transactionProjection.ProductId,
                        PriceId = transactionProjection.PriceId,
                        BillingPeriodStart = transactionProjection.PeriodStart,
                        BillingPeriodEnd = transactionProjection.PeriodEnd
                    };
                    var stale = await ApplyGrantsAsync(connection, transaction, adjusted, price, "revoked", item.OccurredAt, cancellationToken);
                    if (transactionProjection.SubscriptionId is not null)
                        await RecordImmediateRefundIfCompleteAsync(connection, transaction, transactionProjection.SubscriptionId, item.EvidenceScope, cancellationToken);
                    return stale;
                }

            case "customer.portal_session.created":
                await InsertEvidenceAsync(connection, transaction, item.EvidenceScope, "customer-portal", cancellationToken);
                return false;

            default:
                throw new InvalidSimulatorEventException("The signed simulator event type is unsupported.");
        }
    }

    private async Task<bool> ApplyGrantsAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        NormalizedProjectPaymentEvent item,
        ProjectPaymentPrice price,
        string status,
        DateTimeOffset? effectiveUntil,
        CancellationToken cancellationToken)
    {
        var anyApplied = false;
        var sourceKey = price.Type == "recurring"
            ? item.SubscriptionId is not null ? $"subscription:{item.SubscriptionId}" : null
            : item.TransactionId is not null ? $"transaction:{item.TransactionId}" : null;
        if (sourceKey is null)
            throw new InvalidSimulatorEventException("An entitlement effect has no immutable provider source.");

        foreach (var grant in price.Grants)
        {
            var existingSubject = await ScalarTextAsync(connection, transaction, """
                SELECT subject_key FROM project_payment_entitlement_source
                WHERE grant_key=$grant AND source_key=$source;
                """, ("$grant", grant.Entitlement), cancellationToken, ("$source", sourceKey));
            if (existingSubject is not null && existingSubject != item.SubjectKey)
                throw new InvalidSimulatorEventException("An entitlement provider source cannot be rebound to another buyer.");

            var affected = await ExecuteAsync(connection, transaction, """
                INSERT INTO project_payment_entitlement_source(
                  subject_key,grant_key,source_key,provider_subscription_id,provider_transaction_id,
                  quantity,status,effective_from,effective_until,billing_period_start,billing_period_end,
                  source_price_id,source_event_id,last_occurred_at)
                VALUES($subject,$grant,$source,$subscription,$transaction,$quantity,$status,$from,$until,$period_start,$period_end,$price,$event,$occurred)
                ON CONFLICT(subject_key,grant_key,source_key) DO UPDATE SET
                  provider_subscription_id=excluded.provider_subscription_id,provider_transaction_id=excluded.provider_transaction_id,
                  quantity=excluded.quantity,status=excluded.status,effective_from=excluded.effective_from,effective_until=excluded.effective_until,
                  billing_period_start=excluded.billing_period_start,billing_period_end=excluded.billing_period_end,
                  source_price_id=excluded.source_price_id,source_event_id=excluded.source_event_id,last_occurred_at=excluded.last_occurred_at
                WHERE
                  CASE
                    WHEN excluded.billing_period_end IS NOT NULL AND project_payment_entitlement_source.billing_period_end IS NOT NULL
                      THEN excluded.billing_period_end > project_payment_entitlement_source.billing_period_end
                        OR (excluded.billing_period_end = project_payment_entitlement_source.billing_period_end
                          AND ((excluded.status='revoked' AND project_payment_entitlement_source.status!='revoked')
                            OR excluded.last_occurred_at > project_payment_entitlement_source.last_occurred_at
                            OR (excluded.last_occurred_at = project_payment_entitlement_source.last_occurred_at
                              AND excluded.source_event_id > project_payment_entitlement_source.source_event_id)))
                    ELSE (excluded.status='revoked' AND project_payment_entitlement_source.status!='revoked')
                      OR excluded.last_occurred_at > project_payment_entitlement_source.last_occurred_at
                      OR (excluded.last_occurred_at = project_payment_entitlement_source.last_occurred_at
                        AND excluded.source_event_id > project_payment_entitlement_source.source_event_id)
                  END;
                """,
                [("$subject", item.SubjectKey!), ("$grant", grant.Entitlement), ("$source", sourceKey),
                 ("$subscription", item.SubscriptionId), ("$transaction", item.TransactionId),
                 ("$quantity", grant.Quantity), ("$status", status),
                 ("$from", Format(item.BillingPeriodStart ?? item.OccurredAt)), ("$until", effectiveUntil is null ? null : Format(effectiveUntil.Value)),
                 ("$period_start", item.BillingPeriodStart is null ? null : Format(item.BillingPeriodStart.Value)),
                 ("$period_end", item.BillingPeriodEnd is null ? null : Format(item.BillingPeriodEnd.Value)),
                 ("$price", price.ExternalId), ("$event", item.EventId), ("$occurred", Format(item.OccurredAt))], cancellationToken);
            if (affected == 1)
            {
                await RebuildEntitlementAggregateAsync(connection, transaction, item.SubjectKey!, grant.Entitlement, cancellationToken);
                anyApplied = true;
            }
        }
        return !anyApplied;
    }

    private static async Task RebuildEntitlementAggregateAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string subjectKey,
        string grantKey,
        CancellationToken cancellationToken)
    {
        var sources = new List<EntitlementSourceProjection>();
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                SELECT quantity,status,effective_from,effective_until,billing_period_start,billing_period_end,
                       source_price_id,source_event_id,last_occurred_at
                FROM project_payment_entitlement_source
                WHERE subject_key=$subject AND grant_key=$grant;
                """;
            command.Parameters.AddWithValue("$subject", subjectKey);
            command.Parameters.AddWithValue("$grant", grantKey);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
                sources.Add(new(
                    reader.GetInt32(0), reader.GetString(1), Parse(reader.GetString(2)),
                    reader.IsDBNull(3) ? null : Parse(reader.GetString(3)),
                    reader.IsDBNull(4) ? null : Parse(reader.GetString(4)),
                    reader.IsDBNull(5) ? null : Parse(reader.GetString(5)),
                    reader.GetString(6), reader.GetString(7), Parse(reader.GetString(8))));
        }
        if (sources.Count == 0) throw new InvalidOperationException("The entitlement contribution was not persisted.");

        var available = sources.Where(source => source.Status is "active" or "scheduled_cancel").ToArray();
        var latest = sources.OrderByDescending(source => source.LastOccurredAt)
            .ThenByDescending(source => source.SourceEventId, StringComparer.Ordinal).First();
        var aggregateStatus = available.Any(source => source.Status == "active") ? "active"
            : available.Length > 0 ? "scheduled_cancel" : "revoked";
        var activeQuantity = available.Aggregate(0L, (total, source) => checked(total + source.Quantity));
        var quantity = checked((int)(activeQuantity > 0 ? activeQuantity : latest.Quantity));
        var effectiveFrom = available.Length > 0 ? available.Min(source => source.EffectiveFrom) : latest.EffectiveFrom;
        DateTimeOffset? effectiveUntil = available.Length == 0 ? latest.EffectiveUntil
            : available.Any(source => source.EffectiveUntil is null) ? null
            : available.Max(source => source.EffectiveUntil!.Value);
        var periodSource = (available.Length > 0 ? available : sources.ToArray())
            .Where(source => source.BillingPeriodEnd is not null)
            .OrderByDescending(source => source.BillingPeriodEnd)
            .ThenByDescending(source => source.LastOccurredAt)
            .FirstOrDefault() ?? latest;

        await ExecuteAsync(connection, transaction, """
            INSERT INTO project_payment_entitlement(
              subject_key,grant_key,quantity,status,effective_from,effective_until,billing_period_start,billing_period_end,
              source_price_id,source_event_id,last_occurred_at)
            VALUES($subject,$grant,$quantity,$status,$from,$until,$period_start,$period_end,$price,$event,$occurred)
            ON CONFLICT(subject_key,grant_key) DO UPDATE SET
              quantity=excluded.quantity,status=excluded.status,effective_from=excluded.effective_from,effective_until=excluded.effective_until,
              billing_period_start=excluded.billing_period_start,billing_period_end=excluded.billing_period_end,
              source_price_id=excluded.source_price_id,source_event_id=excluded.source_event_id,last_occurred_at=excluded.last_occurred_at;
            """,
            [("$subject", subjectKey), ("$grant", grantKey), ("$quantity", quantity), ("$status", aggregateStatus),
             ("$from", Format(effectiveFrom)), ("$until", effectiveUntil is null ? null : Format(effectiveUntil.Value)),
             ("$period_start", periodSource.BillingPeriodStart is null ? null : Format(periodSource.BillingPeriodStart.Value)),
             ("$period_end", periodSource.BillingPeriodEnd is null ? null : Format(periodSource.BillingPeriodEnd.Value)),
             ("$price", latest.SourcePriceId), ("$event", latest.SourceEventId), ("$occurred", Format(latest.LastOccurredAt))], cancellationToken);
    }

    private static async Task<bool> IsTransactionFencedByRefundAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        NormalizedProjectPaymentEvent item,
        CancellationToken cancellationToken)
    {
        var refund = await ReadRefundByTransactionAsync(connection, transaction, item.TransactionId!, cancellationToken);
        if (refund is null && item.SubscriptionId is not null)
            refund = await ReadLatestRefundBySubscriptionAsync(connection, transaction, item.SubscriptionId, cancellationToken);
        if (refund is null) return false;
        if (item.OccurredAt <= refund.ApprovedAt) return true;
        throw new InvalidSimulatorEventException(item.SubscriptionId is null
            ? "A refunded transaction cannot reactivate an entitlement."
            : "A refunded subscription source cannot be reactivated by another transaction.");
    }

    private static async Task<bool> IsSubscriptionFencedByRefundAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        NormalizedProjectPaymentEvent item,
        CancellationToken cancellationToken)
    {
        var refund = await ReadLatestRefundBySubscriptionAsync(connection, transaction, item.SubscriptionId!, cancellationToken);
        if (refund is null) return false;
        if (item.OccurredAt <= refund.ApprovedAt) return true;
        throw new InvalidSimulatorEventException("A refunded subscription source cannot be reactivated by another subscription event.");
    }

    private static async Task<bool> InsertRefundProjectionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        NormalizedProjectPaymentEvent item,
        string? subscriptionId,
        CancellationToken cancellationToken)
    {
        var inserted = await ExecuteAsync(connection, transaction, """
            INSERT INTO project_payment_refund(provider_transaction_id,provider_subscription_id,source_event_id,approved_at)
            VALUES($transaction,$subscription,$event,$approved)
            ON CONFLICT(provider_transaction_id) DO NOTHING;
            """,
            [("$transaction", item.TransactionId!), ("$subscription", subscriptionId),
             ("$event", item.EventId), ("$approved", Format(item.OccurredAt))], cancellationToken);
        if (inserted == 1) return true;

        var existing = await ReadRefundByTransactionAsync(connection, transaction, item.TransactionId!, cancellationToken)
            ?? throw new InvalidOperationException("The refund projection disappeared during idempotency validation.");
        if (existing.SubscriptionId != subscriptionId || existing.SourceEventId != item.EventId || existing.ApprovedAt != item.OccurredAt)
            throw new InvalidSimulatorEventException("A refunded transaction cannot be rebound to another approval or subscription.");
        return false;
    }

    private async Task RecordImmediateRefundIfCompleteAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string subscriptionId,
        string evidenceScope,
        CancellationToken cancellationToken)
    {
        var subscriptionStatus = await ScalarTextAsync(connection, transaction,
            "SELECT status FROM project_payment_subscription WHERE provider_subscription_id=$subscription;",
            ("$subscription", subscriptionId), cancellationToken);
        if (subscriptionStatus != "revoked") return;
        var refund = await ReadLatestRefundBySubscriptionAsync(connection, transaction, subscriptionId, cancellationToken);
        if (refund is not null)
            await InsertEvidenceAsync(connection, transaction, evidenceScope, "immediate-refund", cancellationToken);
    }

    private static async Task<RefundProjection?> ReadRefundByTransactionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string transactionId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT provider_subscription_id,source_event_id,approved_at FROM project_payment_refund WHERE provider_transaction_id=$transaction;";
        command.Parameters.AddWithValue("$transaction", transactionId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new(reader.IsDBNull(0) ? null : reader.GetString(0), reader.GetString(1), Parse(reader.GetString(2)))
            : null;
    }

    private static async Task<RefundProjection?> ReadLatestRefundBySubscriptionAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string subscriptionId,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT provider_subscription_id,source_event_id,approved_at FROM project_payment_refund
            WHERE provider_subscription_id=$subscription ORDER BY approved_at DESC,source_event_id DESC LIMIT 1;
            """;
        command.Parameters.AddWithValue("$subscription", subscriptionId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new(reader.GetString(0), reader.GetString(1), Parse(reader.GetString(2)))
            : null;
    }

    private async Task<SubscriptionProjection?> ReadSubscriptionAsync(
        SqliteConnection connection, SqliteTransaction transaction, string subscriptionId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT subject_key,product_id,price_id,status,period_start,period_end,last_occurred_at FROM project_payment_subscription WHERE provider_subscription_id=$id;";
        command.Parameters.AddWithValue("$id", subscriptionId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), Parse(reader.GetString(4)), Parse(reader.GetString(5)), Parse(reader.GetString(6)))
            : null;
    }

    private async Task<TransactionProjection?> ReadTransactionAsync(
        SqliteConnection connection, SqliteTransaction transaction, string transactionId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT subject_key,subscription_id,product_id,price_id,amount_minor,currency,period_start,period_end,occurred_at FROM project_payment_transaction WHERE provider_transaction_id=$id;";
        command.Parameters.AddWithValue("$id", transactionId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new(reader.GetString(0), reader.IsDBNull(1) ? null : reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetInt64(4), reader.GetString(5),
                reader.IsDBNull(6) ? null : Parse(reader.GetString(6)), reader.IsDBNull(7) ? null : Parse(reader.GetString(7)), Parse(reader.GetString(8)))
            : null;
    }

    private async Task<TransactionProjection?> ReadFirstTransactionForSubscriptionAsync(
        SqliteConnection connection, SqliteTransaction transaction, string subscriptionId, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            SELECT subject_key,subscription_id,product_id,price_id,amount_minor,currency,period_start,period_end,occurred_at
            FROM project_payment_transaction WHERE subscription_id=$id ORDER BY occurred_at LIMIT 1;
            """;
        command.Parameters.AddWithValue("$id", subscriptionId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken)
            ? new(reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetInt64(4), reader.GetString(5),
                reader.IsDBNull(6) ? null : Parse(reader.GetString(6)), reader.IsDBNull(7) ? null : Parse(reader.GetString(7)), Parse(reader.GetString(8)))
            : null;
    }

    private static void EnsureSameSubscriptionTarget(SubscriptionProjection projection, NormalizedProjectPaymentEvent item)
    {
        if (projection.Subject != item.SubjectKey || projection.ProductId != item.ProductId || projection.PriceId != item.PriceId)
            throw new InvalidSimulatorEventException("A subscription id cannot be rebound to a different buyer or trusted catalog price.");
    }

    private static void EnsureSameTransactionSubscriptionTarget(TransactionProjection projection, NormalizedProjectPaymentEvent item)
    {
        if (projection.Subject != item.SubjectKey || projection.SubscriptionId != item.SubscriptionId
            || projection.ProductId != item.ProductId || projection.PriceId != item.PriceId)
            throw new InvalidSimulatorEventException("A recurring subscription id cannot be rebound through a transaction or subscription event.");
    }

    private async Task RecordFailureAsync(long id, string leaseId, Exception exception, CancellationToken cancellationToken)
    {
        await using var connection = await OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            UPDATE project_payment_webhook_event
            SET attempt_count=attempt_count+1,
                next_attempt_at=$next,
                dead_lettered_at=CASE WHEN attempt_count+1 >= $maximum THEN $now ELSE NULL END,
                last_error=$error,
                lease_id=NULL,lease_expires_at=NULL
            WHERE id=$id AND lease_id=$lease AND processed_at IS NULL;
            """;
        var attempts = await ScalarLongAsync(connection, "SELECT attempt_count FROM project_payment_webhook_event WHERE id=$id;", cancellationToken, ("$id", id));
        var delaySeconds = Math.Min(30 * Math.Pow(2, Math.Min(attempts, 6)), 1800);
        command.Parameters.AddWithValue("$next", Format(_timeProvider.GetUtcNow().AddSeconds(delaySeconds)));
        command.Parameters.AddWithValue("$maximum", MaximumAttempts);
        command.Parameters.AddWithValue("$now", Format(_timeProvider.GetUtcNow()));
        command.Parameters.AddWithValue("$error", exception.GetType().Name);
        command.Parameters.AddWithValue("$id", id);
        command.Parameters.AddWithValue("$lease", leaseId);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private async Task InsertEvidenceAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string evidenceScope,
        string name,
        CancellationToken cancellationToken)
    {
        if (!ProjectPaymentSecurity.ConstantText(evidenceScope, _evidenceScope))
            throw new InvalidOperationException("Lifecycle evidence belongs to a different runtime build scope.");
        if (!RequiredEvidence.Contains(name) && name != "restart-replay") throw new InvalidOperationException("Unknown lifecycle evidence.");
        await ExecuteAsync(connection, transaction,
            "INSERT INTO project_payment_evidence(scope_digest,name,observed_at) VALUES($scope,$name,$now) ON CONFLICT(scope_digest,name) DO NOTHING;",
            [("$scope", evidenceScope), ("$name", name), ("$now", Format(_timeProvider.GetUtcNow()))], cancellationToken);
    }

    private static DateTimeOffset PeriodEnd(DateTimeOffset startsAt, string interval) => interval switch
    {
        "month" => startsAt.AddMonths(1),
        "year" => startsAt.AddYears(1),
        _ => throw new InvalidSimulatorEventException("The trusted recurring interval is invalid.")
    };

    private void ValidateNormalizedEvent(NormalizedProjectPaymentEvent item)
    {
        ProjectPaymentSecurity.RequireIdentifier(item.DestinationKey, "Destination key");
        ProjectPaymentSecurity.RequireIdentifier(item.EventId, "Provider event id");
        if (item.DestinationKey != _catalog.EnvironmentExternalId) throw new InvalidSimulatorEventException("The event destination does not match the runtime environment.");
        if (item.BodyDigest.Length != 64 || item.BodyDigest.Any(value => !Uri.IsHexDigit(value))) throw new InvalidSimulatorEventException("The event body digest is invalid.");
        ValidatePersistedEvidenceScope(item);
    }

    private void ValidatePersistedEvidenceScope(NormalizedProjectPaymentEvent item)
    {
        if (item.EvidenceScope is null || !ProjectPaymentSecurity.ConstantText(item.EvidenceScope, _evidenceScope))
            throw new InvalidSimulatorEventException("The durable simulator event belongs to a different runtime build scope.");
    }

    private void Initialize()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = Schema;
        command.ExecuteNonQuery();
        MigrateLegacyEvidence(connection);
        MigrateLegacyEntitlementContributions(connection);
    }

    private static void MigrateLegacyEvidence(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        var hasScope = false;
        using (var inspect = connection.CreateCommand())
        {
            inspect.Transaction = transaction;
            inspect.CommandText = "PRAGMA table_info(project_payment_evidence);";
            using var reader = inspect.ExecuteReader();
            while (reader.Read()) hasScope |= reader.GetString(1) == "scope_digest";
        }
        using (var removeLegacyMarker = connection.CreateCommand())
        {
            removeLegacyMarker.Transaction = transaction;
            removeLegacyMarker.CommandText = "DROP TABLE IF EXISTS project_payment_metadata;";
            removeLegacyMarker.ExecuteNonQuery();
        }
        if (hasScope)
        {
            transaction.Commit();
            return;
        }
        using var migrate = connection.CreateCommand();
        migrate.Transaction = transaction;
        migrate.CommandText = """
            DROP TABLE project_payment_evidence;
            CREATE TABLE project_payment_evidence (
              scope_digest TEXT NOT NULL,
              name TEXT NOT NULL,
              observed_at TEXT NOT NULL,
              PRIMARY KEY(scope_digest,name)
            );
            """;
        migrate.ExecuteNonQuery();
        transaction.Commit();
    }

    private static void MigrateLegacyEntitlementContributions(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var migrate = connection.CreateCommand();
        migrate.Transaction = transaction;
        migrate.CommandText = """
            INSERT INTO project_payment_entitlement_source(
              subject_key,grant_key,source_key,provider_subscription_id,provider_transaction_id,
              quantity,status,effective_from,effective_until,billing_period_start,billing_period_end,
              source_price_id,source_event_id,last_occurred_at)
            SELECT e.subject_key,e.grant_key,'legacy:' || CAST(e.id AS TEXT),NULL,NULL,
                   e.quantity,e.status,e.effective_from,e.effective_until,e.billing_period_start,e.billing_period_end,
                   e.source_price_id,e.source_event_id,e.last_occurred_at
            FROM project_payment_entitlement e
            WHERE NOT EXISTS (
              SELECT 1 FROM project_payment_entitlement_source source
              WHERE source.subject_key=e.subject_key AND source.grant_key=e.grant_key
            );
            """;
        migrate.ExecuteNonQuery();
        transaction.Commit();
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;";
        await command.ExecuteNonQueryAsync(cancellationToken);
        return connection;
    }

    private static async Task<int> ExecuteAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string sql,
        IReadOnlyList<(string Name, object? Value)> parameters,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<string?> ScalarTextAsync(
        SqliteConnection connection,
        SqliteTransaction? transaction,
        string sql,
        (string Name, object? Value)? parameter = null,
        CancellationToken cancellationToken = default,
        params (string Name, object? Value)[] additionalParameters)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        if (parameter is { } item) command.Parameters.AddWithValue(item.Name, item.Value ?? DBNull.Value);
        foreach (var (name, value) in additionalParameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return (string?)await command.ExecuteScalarAsync(cancellationToken);
    }

    private static async Task<long> ScalarLongAsync(
        SqliteConnection connection,
        string sql,
        CancellationToken cancellationToken,
        params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken), CultureInfo.InvariantCulture);
    }

    private static string Format(DateTimeOffset value) => value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static DateTimeOffset Parse(string value) => DateTimeOffset.ParseExact(value, "O", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);

    private sealed record SubscriptionProjection(
        string Subject,
        string ProductId,
        string PriceId,
        string Status,
        DateTimeOffset Start,
        DateTimeOffset End,
        DateTimeOffset LastOccurredAt);

    private sealed record TransactionProjection(
        string Subject,
        string? SubscriptionId,
        string ProductId,
        string PriceId,
        long AmountMinor,
        string Currency,
        DateTimeOffset? PeriodStart,
        DateTimeOffset? PeriodEnd,
        DateTimeOffset OccurredAt);

    private sealed record RefundProjection(
        string? SubscriptionId,
        string SourceEventId,
        DateTimeOffset ApprovedAt);

    private sealed record EntitlementSourceProjection(
        int Quantity,
        string Status,
        DateTimeOffset EffectiveFrom,
        DateTimeOffset? EffectiveUntil,
        DateTimeOffset? BillingPeriodStart,
        DateTimeOffset? BillingPeriodEnd,
        string SourcePriceId,
        string SourceEventId,
        DateTimeOffset LastOccurredAt);

    private sealed class RetryableProjectPaymentDependencyException(string message) : InvalidOperationException(message);

    private const string Schema = """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS project_payment_webhook_event (
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
        CREATE INDEX IF NOT EXISTS ix_project_payment_webhook_event_due
          ON project_payment_webhook_event(next_attempt_at,received_at)
          WHERE processed_at IS NULL AND dead_lettered_at IS NULL;
        CREATE TABLE IF NOT EXISTS project_payment_customer_binding (
          provider_customer_id TEXT PRIMARY KEY,
          subject_key TEXT NOT NULL UNIQUE,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS project_payment_entitlement (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject_key TEXT NOT NULL,
          grant_key TEXT NOT NULL,
          quantity INTEGER NOT NULL CHECK(quantity > 0),
          status TEXT NOT NULL CHECK(status IN ('active','scheduled_cancel','revoked','expired')),
          effective_from TEXT NOT NULL,
          effective_until TEXT NULL,
          billing_period_start TEXT NULL,
          billing_period_end TEXT NULL,
          source_price_id TEXT NOT NULL,
          source_event_id TEXT NOT NULL,
          last_occurred_at TEXT NOT NULL,
          UNIQUE(subject_key,grant_key)
        );
        CREATE TABLE IF NOT EXISTS project_payment_entitlement_source (
          subject_key TEXT NOT NULL,
          grant_key TEXT NOT NULL,
          source_key TEXT NOT NULL,
          provider_subscription_id TEXT NULL,
          provider_transaction_id TEXT NULL,
          quantity INTEGER NOT NULL CHECK(quantity > 0),
          status TEXT NOT NULL CHECK(status IN ('active','scheduled_cancel','revoked','expired')),
          effective_from TEXT NOT NULL,
          effective_until TEXT NULL,
          billing_period_start TEXT NULL,
          billing_period_end TEXT NULL,
          source_price_id TEXT NOT NULL,
          source_event_id TEXT NOT NULL,
          last_occurred_at TEXT NOT NULL,
          PRIMARY KEY(subject_key,grant_key,source_key),
          UNIQUE(grant_key,source_key)
        );
        CREATE TABLE IF NOT EXISTS project_payment_transaction (
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
        CREATE TABLE IF NOT EXISTS project_payment_subscription (
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
        CREATE TABLE IF NOT EXISTS project_payment_refund (
          provider_transaction_id TEXT PRIMARY KEY,
          provider_subscription_id TEXT NULL,
          source_event_id TEXT NOT NULL,
          approved_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_project_payment_refund_subscription
          ON project_payment_refund(provider_subscription_id,approved_at);
        CREATE TABLE IF NOT EXISTS project_payment_evidence (
          scope_digest TEXT NOT NULL,
          name TEXT NOT NULL,
          observed_at TEXT NOT NULL,
          PRIMARY KEY(scope_digest,name)
        );
        """;
}
