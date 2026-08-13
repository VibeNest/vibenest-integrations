using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fixture.ProjectPayments;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;

const string environmentId = "sim_env_fixture";
const string secret = "0123456789abcdef0123456789abcdef"; // gitleaks:allow -- deterministic simulator fixture, not a credential
var digest = new string('b', 64);
var commit = new string('a', 40);
var evidenceScope = ProjectPaymentEvidenceScope.Compute(environmentId, digest, commit);
var directory = Path.Combine(Path.GetTempPath(), $"vn-pp-dotnet-{Guid.NewGuid():N}");
Directory.CreateDirectory(directory);

try
{
    var catalogProjection = CatalogProjection(environmentId, digest);
    var catalog = ProjectPaymentCatalog.Parse(EncodeCatalog(catalogProjection), environmentId, digest);
    var independentlyScoped = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"vibenest-project-payments-evidence-v1\0{environmentId}\0{digest}\0{commit}")));
    Ensure(evidenceScope == independentlyScoped, "runtime evidence scope does not match the finalized cross-adapter formula");
    Ensure(catalog.ResolveByManifestKey("monthly").Grants.Single().Quantity == 2, "trusted grant quantity was lost");
    MustThrow(() => ProjectPaymentCatalog.Parse(EncodeCatalog(CatalogProjection("sim_env_forged", digest)), environmentId, digest));
    MustThrow(() => ProjectPaymentCatalog.Parse(EncodeCatalog(CatalogProjection(environmentId, new string('c', 64))), environmentId, digest));
    MustThrow(() => ProjectPaymentCatalog.Parse(Convert.ToBase64String(Encoding.UTF8.GetBytes("{}")) + " ", environmentId, digest));

    var rawSignatureBody = Encoding.UTF8.GetBytes("{\n  \"signed\": true\n}\n");
    var signedAt = DateTimeOffset.UtcNow;
    var signature = ProjectPaymentSignature.Sign(rawSignatureBody, secret, signedAt);
    Ensure(ProjectPaymentSignature.Verify(rawSignatureBody, signature, secret, signedAt), "valid raw byte signature failed");
    Ensure(!ProjectPaymentSignature.Verify([.. rawSignatureBody, (byte)' '], signature, secret, signedAt), "tampered raw bytes were accepted");
    Ensure(!ProjectPaymentSignature.Verify(rawSignatureBody, signature, "short", signedAt), "weak runtime secret was accepted");
    await TestBoundedWebhookBodyReader();
    await TestRestartReplayHarness(Path.Combine(directory, "restart-harness.sqlite"), catalog, evidenceScope, digest, commit);
    await TestMigrationArtifacts(directory);

    var database = Path.Combine(directory, "lifecycle.sqlite");
    var receiver = new DurableProjectPaymentStore(database, catalog, evidenceScope, instanceId: "receiver-instance");
    var provider = new SimulatorProjectPaymentProvider(catalog, receiver, TimeProvider.System);
    await provider.PreviewPricesAsync(["monthly", "lifetime"]);
    await provider.CreatePortalAsync("buyer-subscription");
    await provider.CreateCheckoutAsync("buyer-subscription", "monthly");
    await provider.CreateCheckoutAsync("buyer-onetime", "lifetime");
    await provider.CreateCheckoutAsync("buyer-duplicate", "lifetime");
    await provider.CreateCheckoutAsync("buyer-declined", "lifetime");
    await provider.CreateCheckoutAsync("buyer-stale", "monthly");

    var t0 = new DateTimeOffset(2026, 8, 8, 10, 0, 0, TimeSpan.Zero);
    var firstPeriod = Period(t0, t0.AddMonths(1));
    var renewedPeriod = Period(t0.AddMonths(1), t0.AddMonths(2));

    await Deliver(receiver, catalog, Transaction("evt-one", "transaction.completed", t0, "buyer-onetime", "lifetime", null, "sim_txn_one", null));
    await Deliver(receiver, catalog, Subscription("evt-sub-create", "subscription.created", t0.AddSeconds(1), "buyer-subscription", "sim_sub_main", firstPeriod, null));
    await Deliver(receiver, catalog, Transaction("evt-sub-tx", "transaction.completed", t0.AddSeconds(1).AddMilliseconds(1), "buyer-subscription", "monthly", "sim_sub_main", "sim_txn_first", firstPeriod));
    await Deliver(receiver, catalog, Transaction("evt-declined", "transaction.payment_failed", t0.AddSeconds(2), "buyer-declined", "lifetime", null, "sim_txn_declined", null, "declined"));

    var duplicatePayload = Transaction("evt-duplicate", "transaction.completed", t0.AddSeconds(3), "buyer-duplicate", "lifetime", null, "sim_txn_duplicate", null);
    var duplicateResults = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Deliver(receiver, catalog, duplicatePayload)));
    Ensure(duplicateResults.Count(value => value) == 1, "concurrent duplicate delivery inserted more than once");

    await Deliver(receiver, catalog, Subscription("evt-renewal", "subscription.updated", t0.AddMonths(1), "buyer-subscription", "sim_sub_main", renewedPeriod, null));
    await Deliver(receiver, catalog, Transaction("evt-renewal-tx", "transaction.completed", t0.AddMonths(1).AddMilliseconds(1), "buyer-subscription", "monthly", "sim_sub_main", "sim_txn_renewal", renewedPeriod));
    await Deliver(receiver, catalog, Subscription("evt-scheduled", "subscription.updated", t0.AddMonths(1).AddSeconds(1), "buyer-subscription", "sim_sub_main", renewedPeriod, renewedPeriod.EndsAt));

    await Deliver(receiver, catalog, Adjustment("evt-adjustment-pending", "adjustment.created", t0.AddMonths(1).AddSeconds(2), "sim_adj_main", "sim_txn_renewal", "pending_approval"));
    await Deliver(receiver, catalog, Adjustment("evt-adjustment-approved", "adjustment.updated", t0.AddMonths(1).AddSeconds(2).AddMilliseconds(1), "sim_adj_main", "sim_txn_renewal", "approved"));
    await Deliver(receiver, catalog, Subscription("evt-sub-canceled", "subscription.canceled", t0.AddMonths(1).AddSeconds(2).AddMilliseconds(2), "buyer-subscription", "sim_sub_main", renewedPeriod, null, "canceled"));

    var staleSubscription = Subscription("evt-stale-sub", "subscription.created", t0.AddSeconds(5), "buyer-stale", "sim_sub_stale", firstPeriod, null);
    var newerTransaction = Transaction("evt-stale-tx", "transaction.completed", t0.AddSeconds(5).AddMilliseconds(2), "buyer-stale", "monthly", "sim_sub_stale", "sim_txn_stale", firstPeriod);
    await Deliver(receiver, catalog, newerTransaction);
    await Deliver(receiver, catalog, staleSubscription);

    var processor = new DurableProjectPaymentStore(database, catalog, evidenceScope, instanceId: "processor-after-restart");
    Ensure(await processor.ProcessDueAsync() > 0, "durable inbox did not resume after restart");
    var snapshot = await processor.SnapshotAsync();
    Ensure(snapshot.Events.Single(item => item.EventId == "evt-duplicate").DeliveryCount == 6, "duplicate delivery count was not durable");
    Ensure(snapshot.Events.Single(item => item.EventId == "evt-stale-sub").IgnoredAsStale, "older event was not fenced");
    Ensure(snapshot.Entitlements["buyer-onetime:premium-access"].Quantity == 2, "runtime grant quantity was not applied exactly once");
    Ensure(snapshot.Entitlements["buyer-subscription:premium-access"].Status == "revoked", "approved refund did not revoke entitlement");
    Ensure(snapshot.RestartReplayObserved, "restart replay evidence was not derived from durable ownership");

    var verification = await ProjectPaymentVerifier.BuildAsync(
        new(ProjectPaymentProviderMode.Simulator, true, true, secret, commit, digest, environmentId, EncodeCatalog(catalogProjection)),
        secret,
        commit,
        digest,
        processor);
    Ensure(verification is { Provider: "simulator", LifecyclePassed: true, DurableInbox: true, RestartReplayPassed: true }, "verifier did not derive complete lifecycle evidence");
    Ensure(await ProjectPaymentVerifier.BuildAsync(
        new(ProjectPaymentProviderMode.Simulator, true, true, secret, string.Empty, digest, environmentId, EncodeCatalog(catalogProjection)),
        secret, commit, digest, processor) is null, "request challenge substituted for missing SOURCE_COMMIT");
    Ensure(await ProjectPaymentVerifier.BuildAsync(
        new(ProjectPaymentProviderMode.Disabled, false, false, string.Empty, string.Empty, digest, environmentId, string.Empty),
        secret, commit, digest, processor) is null, "disabled mode exposed the verifier");

    var replacementCommit = new string('c', 40);
    var replacementScope = ProjectPaymentEvidenceScope.Compute(environmentId, digest, replacementCommit);
    Ensure(await ProjectPaymentVerifier.BuildAsync(
        new(ProjectPaymentProviderMode.Simulator, true, true, secret, replacementCommit, digest, environmentId, EncodeCatalog(catalogProjection)),
        secret, replacementCommit, digest, processor) is null,
        "the verifier did not recompute and compare the exact runtime evidence scope");
    var replacementRuntime = new DurableProjectPaymentStore(database, catalog, replacementScope, instanceId: "replacement-build");
    Ensure(!(await replacementRuntime.VerificationStatusAsync(replacementScope)).LifecyclePassed,
        "evidence from the previous exact SOURCE_COMMIT leaked into a replacement build");
    Ensure(await ProjectPaymentVerifier.BuildAsync(
        new(ProjectPaymentProviderMode.Simulator, true, true, secret, replacementCommit, digest, environmentId, EncodeCatalog(catalogProjection)),
        secret, replacementCommit, digest, replacementRuntime) is null,
        "the verifier accepted lifecycle evidence earned by a different exact build");

    await TestExpiredLeaseRecovery(Path.Combine(directory, "lease.sqlite"), catalog, evidenceScope);
    await TestForgedPayloads(Path.Combine(directory, "forged.sqlite"), catalog, evidenceScope, t0);
    await TestSubscriptionIdentityAndReactivationFences(directory, catalog, evidenceScope, t0);
    await TestIndependentPaidSourcesAndRefundConvergence(Path.Combine(directory, "source-contributions.sqlite"), catalog, evidenceScope, t0);
    await TestOldPendingEventScope(Path.Combine(directory, "old-scope.sqlite"), catalog, evidenceScope, replacementScope, t0);
    await TestLegacyUnscopedEvidenceMigration(Path.Combine(directory, "legacy-evidence.sqlite"), catalog, evidenceScope);
    await TestLegacyEntitlementContributionMigration(Path.Combine(directory, "legacy-entitlement.sqlite"), catalog, evidenceScope);

    var disabled = new DisabledProjectPaymentProvider();
    await MustThrowAsync(() => disabled.CreateCheckoutAsync("buyer", "monthly"));
    Console.WriteLine("ASP.NET Core Project Payments fixture: PASS");
}
finally
{
    SqliteConnection.ClearAllPools();
    Directory.Delete(directory, recursive: true);
}

async Task TestMigrationArtifacts(string directory)
{
    var migrationsDirectory = Path.Combine(AppContext.BaseDirectory, "migrations");
    var initialSql = await File.ReadAllTextAsync(Path.Combine(migrationsDirectory, "001_project_payments.sql"));
    var upgradeSql = await File.ReadAllTextAsync(Path.Combine(migrationsDirectory, "002_entitlement_source_contributions.sql"));

    var freshPath = Path.Combine(directory, "migration-fresh.sqlite");
    await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
    {
        DataSource = freshPath,
        Pooling = false,
    }.ToString()))
    {
        await connection.OpenAsync();
        await ExecuteSqlAsync(connection, initialSql);
        await ExecuteSqlAsync(connection, upgradeSql);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT COUNT(*) FROM sqlite_master
            WHERE type='table' AND name IN ('project_payment_entitlement_source','project_payment_refund');
            """;
        Ensure(Convert.ToInt32(await command.ExecuteScalarAsync()) == 2,
            "fresh migration artifacts did not create the source/refund projections");
    }

    var legacyPath = Path.Combine(directory, "migration-legacy.sqlite");
    await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder
    {
        DataSource = legacyPath,
        Pooling = false,
    }.ToString()))
    {
        await connection.OpenAsync();
        await ExecuteSqlAsync(connection, """
            CREATE TABLE project_payment_entitlement (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subject_key TEXT NOT NULL,
                grant_key TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                status TEXT NOT NULL,
                effective_from TEXT NOT NULL,
                effective_until TEXT NULL,
                billing_period_start TEXT NULL,
                billing_period_end TEXT NULL,
                source_price_id TEXT NOT NULL,
                source_event_id TEXT NOT NULL,
                last_occurred_at TEXT NOT NULL,
                UNIQUE(subject_key, grant_key));
            INSERT INTO project_payment_entitlement(
                subject_key,grant_key,quantity,status,effective_from,effective_until,
                billing_period_start,billing_period_end,source_price_id,source_event_id,last_occurred_at)
            VALUES('buyer-artifact','premium-access',2,'active','2026-08-01T00:00:00Z',NULL,
                   NULL,NULL,'sim_price_lifetime','evt-artifact','2026-08-01T00:00:00Z');
            """);
        await ExecuteSqlAsync(connection, upgradeSql);
        await using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT source_key || ':' || status || ':' || quantity
            FROM project_payment_entitlement_source
            WHERE subject_key='buyer-artifact' AND grant_key='premium-access';
            """;
        Ensure((string?)await command.ExecuteScalarAsync() == "legacy:1:active:2",
            "upgrade migration artifact did not conservatively backfill the legacy entitlement source");
    }
}

static async Task ExecuteSqlAsync(SqliteConnection connection, string sql)
{
    await using var command = connection.CreateCommand();
    command.CommandText = sql;
    await command.ExecuteNonQueryAsync();
}

async Task TestExpiredLeaseRecovery(string path, ProjectPaymentCatalog catalog, string scope)
{
    var receiving = new DurableProjectPaymentStore(path, catalog, scope, instanceId: "lease-receiver");
    await new SimulatorProjectPaymentProvider(catalog, receiving, TimeProvider.System).CreateCheckoutAsync("buyer-lease", "lifetime");
    await Deliver(receiving, catalog, Transaction("evt-lease", "transaction.completed", DateTimeOffset.UtcNow, "buyer-lease", "lifetime", null, "sim_txn_lease", null));
    await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
    {
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "UPDATE project_payment_webhook_event SET lease_id='abandoned', lease_expires_at=$expired;";
        command.Parameters.AddWithValue("$expired", DateTimeOffset.UtcNow.AddMinutes(-5).ToString("O"));
        await command.ExecuteNonQueryAsync();
    }
    var recovery = new DurableProjectPaymentStore(path, catalog, scope, instanceId: "lease-recovery");
    Ensure(await recovery.ProcessDueAsync() == 1, "expired lease was not recovered");
    Ensure((await recovery.SnapshotAsync()).Events.Single().Processed, "recovered lease was not processed");
}

async Task TestBoundedWebhookBodyReader()
{
    var oversized = Enumerable.Range(0, ProjectPaymentWebhookBodyReader.MaxBodyBytes + 1)
        .Select(index => (byte)(index % 251))
        .ToArray();
    var oversizedStream = new ChunkedReadStream(oversized, 7919);
    var oversizedContext = new DefaultHttpContext();
    oversizedContext.Request.ContentLength = null;
    oversizedContext.Request.Headers.TransferEncoding = "chunked";
    oversizedContext.Request.Body = oversizedStream;
    Ensure(await ProjectPaymentWebhookBodyReader.TryReadAsync(oversizedContext.Request) is null,
        "an oversized chunked body with unknown Content-Length was accepted");
    Ensure(oversizedStream.BytesRead == ProjectPaymentWebhookBodyReader.MaxBodyBytes + 1,
        "the oversized body reader consumed more than the single detection byte");

    var boundary = oversized.AsSpan(0, ProjectPaymentWebhookBodyReader.MaxBodyBytes).ToArray();
    var boundaryContext = new DefaultHttpContext();
    boundaryContext.Request.ContentLength = null;
    boundaryContext.Request.Headers.TransferEncoding = "chunked";
    boundaryContext.Request.Body = new ChunkedReadStream(boundary, 4093);
    var accepted = await ProjectPaymentWebhookBodyReader.TryReadAsync(boundaryContext.Request);
    Ensure(accepted is not null && accepted.AsSpan().SequenceEqual(boundary),
        "a valid body at the exact 1 MiB boundary was rejected or its raw bytes changed");
}

async Task TestRestartReplayHarness(
    string path,
    ProjectPaymentCatalog catalog,
    string scope,
    string manifestDigest,
    string sourceCommit)
{
    var configuration = new ProjectPaymentRuntimeConfiguration(
        ProjectPaymentProviderMode.Simulator,
        true,
        true,
        secret,
        sourceCommit,
        manifestDigest,
        environmentId,
        EncodeCatalog(CatalogProjection(environmentId, manifestDigest)));
    Ensure(ProjectPaymentRestartReplayHarness.IsAuthorized(configuration, secret),
        "the protected simulator harness rejected its server-owned secret");
    Ensure(!ProjectPaymentRestartReplayHarness.IsAuthorized(configuration, new string('x', 32)),
        "the protected simulator harness accepted another secret");
    Ensure(!ProjectPaymentRestartReplayHarness.IsAuthorized(configuration with { VerifierEnabled = false }, secret),
        "the restart harness was exposed outside verifier-enabled simulator mode");
    Ensure(ProjectPaymentRestartReplayHarness.MatchesExpectedBuild(configuration, commit, manifestDigest),
        "the restart harness rejected its exact build challenges");
    Ensure(!ProjectPaymentRestartReplayHarness.MatchesExpectedBuild(configuration, new string('f', 40), manifestDigest),
        "the restart harness accepted another build commit");
    Ensure(!ProjectPaymentRestartReplayHarness.MatchesExpectedBuild(configuration, commit, new string('e', 64)),
        "the restart harness accepted another manifest digest");

    var validContext = new DefaultHttpContext();
    validContext.Request.ContentType = "application/json";
    validContext.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"action\":\"restart-replay\"}"));
    Ensure(await ProjectPaymentRestartReplayHarness.ReadBodyAsync(validContext.Request) == ProjectPaymentHarnessBodyStatus.Valid,
        "the exact restart-replay harness body was rejected");
    var invalidContext = new DefaultHttpContext();
    invalidContext.Request.ContentType = "application/json";
    invalidContext.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes("{\"action\":\"restart-replay\",\"extra\":true}"));
    Ensure(await ProjectPaymentRestartReplayHarness.ReadBodyAsync(invalidContext.Request) == ProjectPaymentHarnessBodyStatus.Invalid,
        "the harness accepted unexpected JSON fields");
    var oversizedContext = new DefaultHttpContext();
    oversizedContext.Request.ContentLength = null;
    oversizedContext.Request.Headers.TransferEncoding = "chunked";
    oversizedContext.Request.Body = new ChunkedReadStream(new byte[ProjectPaymentRestartReplayHarness.MaxBodyBytes + 1], 137);
    Ensure(await ProjectPaymentRestartReplayHarness.ReadBodyAsync(oversizedContext.Request) == ProjectPaymentHarnessBodyStatus.TooLarge,
        "the harness accepted an oversized chunked JSON body");

    var beforeRestart = new DurableProjectPaymentStore(path, catalog, scope, instanceId: "harness-before-restart");
    await beforeRestart.StageRestartReplayProbeAsync(environmentId);
    await beforeRestart.StageRestartReplayProbeAsync(environmentId);
    Ensure(await beforeRestart.ProcessDueAsync() == 0,
        "the process that staged the restart probe was allowed to consume it");
    var staged = await beforeRestart.SnapshotAsync();
    Ensure(staged.Events.Count == 1 && !staged.Events[0].Processed && staged.Events[0].AttemptCount == 0,
        "the idempotent restart probe was not left pending for another boot instance");

    var afterRestart = new DurableProjectPaymentStore(path, catalog, scope, instanceId: "harness-after-restart");
    Ensure(await afterRestart.ProcessDueAsync() == 1,
        "a new process instance did not resume the exact durable restart probe");
    var resumed = await afterRestart.SnapshotAsync();
    Ensure(resumed.Events.Single().Processed && resumed.RestartReplayObserved,
        "restart-replay evidence was not durably earned by the new process instance");
}

async Task TestForgedPayloads(string path, ProjectPaymentCatalog catalog, string scope, DateTimeOffset occurredAt)
{
    var store = new DurableProjectPaymentStore(path, catalog, scope, instanceId: "forgery-receiver");
    await new SimulatorProjectPaymentProvider(catalog, store, TimeProvider.System).CreateCheckoutAsync("buyer-forgery", "monthly");
    var forgedProduct = Transaction("evt-forged-product", "transaction.completed", occurredAt, "buyer-forgery", "monthly", "sim_sub_forged", "sim_txn_forged", Period(occurredAt, occurredAt.AddMonths(1)));
    forgedProduct["data"]!.AsObject()["items"]!.AsArray()[0]!.AsObject()["product_id"] = "sim_prod_attacker";
    await MustThrowAsync(() => NormalizeOnly(store, catalog, forgedProduct));

    var forgedPeriod = Transaction("evt-forged-period", "transaction.completed", occurredAt, "buyer-forgery", "monthly", "sim_sub_forged", "sim_txn_forged_period", Period(occurredAt, occurredAt.AddDays(30)));
    await MustThrowAsync(() => NormalizeOnly(store, catalog, forgedPeriod));

    var unknownBuyer = Transaction("evt-forged-buyer", "transaction.completed", occurredAt, "attacker", "monthly", "sim_sub_forged", "sim_txn_forged_buyer", Period(occurredAt, occurredAt.AddMonths(1)));
    await MustThrowAsync(() => NormalizeOnly(store, catalog, unknownBuyer));
}

async Task TestSubscriptionIdentityAndReactivationFences(
    string root,
    ProjectPaymentCatalog catalog,
    string scope,
    DateTimeOffset occurredAt)
{
    var period = Period(occurredAt, occurredAt.AddMonths(1));

    var transactionFirst = new DurableProjectPaymentStore(Path.Combine(root, "identity-transaction-first.sqlite"), catalog, scope, instanceId: "identity-tx-first");
    var transactionFirstProvider = new SimulatorProjectPaymentProvider(catalog, transactionFirst, TimeProvider.System);
    await transactionFirstProvider.CreateCheckoutAsync("buyer-identity-a", "monthly");
    await transactionFirstProvider.CreateCheckoutAsync("buyer-identity-b", "monthly");
    await Deliver(transactionFirst, catalog, Transaction(
        "evt-identity-tx-first", "transaction.completed", occurredAt, "buyer-identity-a", "monthly",
        "sim_sub_identity_tx_first", "sim_txn_identity_tx_first", period));
    Ensure(await transactionFirst.ProcessDueAsync() == 1, "transaction-first projection was not applied");
    await Deliver(transactionFirst, catalog, Subscription(
        "evt-identity-sub-rebind", "subscription.created", occurredAt.AddSeconds(1), "buyer-identity-b",
        "sim_sub_identity_tx_first", period, null));
    _ = await transactionFirst.ProcessDueAsync();
    var transactionFirstSnapshot = await transactionFirst.SnapshotAsync();
    Ensure(transactionFirstSnapshot.Events.Single(item => item.EventId == "evt-identity-sub-rebind").AttemptCount == 1,
        "a subscription event rebound a transaction-first subscription id");
    Ensure(!transactionFirstSnapshot.Entitlements.ContainsKey("buyer-identity-b:premium-access"),
        "transaction-first identity rebinding granted the attacker entitlement");

    var subscriptionFirst = new DurableProjectPaymentStore(Path.Combine(root, "identity-subscription-first.sqlite"), catalog, scope, instanceId: "identity-sub-first");
    var subscriptionFirstProvider = new SimulatorProjectPaymentProvider(catalog, subscriptionFirst, TimeProvider.System);
    await subscriptionFirstProvider.CreateCheckoutAsync("buyer-sub-first-a", "monthly");
    await subscriptionFirstProvider.CreateCheckoutAsync("buyer-sub-first-b", "monthly");
    await Deliver(subscriptionFirst, catalog, Subscription(
        "evt-identity-sub-first", "subscription.created", occurredAt, "buyer-sub-first-a",
        "sim_sub_identity_sub_first", period, null));
    Ensure(await subscriptionFirst.ProcessDueAsync() == 1, "subscription-first projection was not applied");
    await Deliver(subscriptionFirst, catalog, Transaction(
        "evt-identity-tx-rebind", "transaction.completed", occurredAt.AddSeconds(1), "buyer-sub-first-b", "monthly",
        "sim_sub_identity_sub_first", "sim_txn_identity_rebind", period));
    _ = await subscriptionFirst.ProcessDueAsync();
    var subscriptionFirstSnapshot = await subscriptionFirst.SnapshotAsync();
    Ensure(subscriptionFirstSnapshot.Events.Single(item => item.EventId == "evt-identity-tx-rebind").AttemptCount == 1,
        "a transaction event rebound a subscription-first subscription id");
    Ensure(!subscriptionFirstSnapshot.Entitlements.ContainsKey("buyer-sub-first-b:premium-access"),
        "subscription-first identity rebinding granted the attacker entitlement");

    var lifecycle = new DurableProjectPaymentStore(Path.Combine(root, "non-active-reactivation.sqlite"), catalog, scope, instanceId: "reactivation-fence");
    var lifecycleProvider = new SimulatorProjectPaymentProvider(catalog, lifecycle, TimeProvider.System);
    await lifecycleProvider.CreateCheckoutAsync("buyer-reactivation", "monthly");
    await Deliver(lifecycle, catalog, Subscription(
        "evt-reactivation-created", "subscription.created", occurredAt, "buyer-reactivation",
        "sim_sub_reactivation", period, null));
    Ensure(await lifecycle.ProcessDueAsync() == 1, "reactivation source subscription was not applied");
    await Deliver(lifecycle, catalog, Subscription(
        "evt-reactivation-scheduled", "subscription.updated", occurredAt.AddSeconds(1), "buyer-reactivation",
        "sim_sub_reactivation", period, period.EndsAt));
    Ensure(await lifecycle.ProcessDueAsync() == 1, "scheduled cancellation was not applied");
    await Deliver(lifecycle, catalog, Transaction(
        "evt-reactivation-while-scheduled", "transaction.completed", occurredAt.AddSeconds(2), "buyer-reactivation", "monthly",
        "sim_sub_reactivation", "sim_txn_reactivation_scheduled", period));
    _ = await lifecycle.ProcessDueAsync();
    var scheduledSnapshot = await lifecycle.SnapshotAsync();
    Ensure(scheduledSnapshot.Events.Single(item => item.EventId == "evt-reactivation-while-scheduled").AttemptCount == 1,
        "a same-period transaction reactivated scheduled cancellation");
    Ensure(scheduledSnapshot.Entitlements["buyer-reactivation:premium-access"].Status == "scheduled_cancel",
        "scheduled cancellation entitlement regressed to active");

    await Deliver(lifecycle, catalog, Subscription(
        "evt-reactivation-canceled", "subscription.canceled", occurredAt.AddSeconds(3), "buyer-reactivation",
        "sim_sub_reactivation", period, null, "canceled"));
    Ensure(await lifecycle.ProcessDueAsync() == 1, "immediate cancellation was not applied");
    await Deliver(lifecycle, catalog, Transaction(
        "evt-reactivation-after-revoke", "transaction.completed", occurredAt.AddSeconds(4), "buyer-reactivation", "monthly",
        "sim_sub_reactivation", "sim_txn_reactivation_revoked", period));
    _ = await lifecycle.ProcessDueAsync();
    var revokedSnapshot = await lifecycle.SnapshotAsync();
    Ensure(revokedSnapshot.Events.Single(item => item.EventId == "evt-reactivation-after-revoke").AttemptCount == 1,
        "a same-period transaction reactivated revoked access");
    Ensure(revokedSnapshot.Entitlements["buyer-reactivation:premium-access"].Status == "revoked",
        "revoked entitlement regressed to active");
}

async Task TestIndependentPaidSourcesAndRefundConvergence(
    string path,
    ProjectPaymentCatalog catalog,
    string scope,
    DateTimeOffset occurredAt)
{
    var store = new DurableProjectPaymentStore(path, catalog, scope, instanceId: "source-contributions");
    var provider = new SimulatorProjectPaymentProvider(catalog, store, TimeProvider.System);
    const string buyer = "buyer-combined";
    const string subscriptionId = "sim_sub_combined";
    const string recurringTransactionId = "sim_txn_combined_recurring";
    var period = Period(occurredAt, occurredAt.AddMonths(1));
    await provider.CreateCheckoutAsync(buyer, "lifetime");
    await provider.CreateCheckoutAsync(buyer, "monthly");

    await Deliver(store, catalog, Transaction(
        "evt-combined-lifetime", "transaction.completed", occurredAt, buyer, "lifetime", null,
        "sim_txn_combined_lifetime", null));
    await Deliver(store, catalog, Subscription(
        "evt-combined-subscription", "subscription.created", occurredAt.AddMilliseconds(1), buyer,
        subscriptionId, period, null));
    await Deliver(store, catalog, Transaction(
        "evt-combined-recurring", "transaction.completed", occurredAt.AddMilliseconds(2), buyer, "monthly",
        subscriptionId, recurringTransactionId, period));
    Ensure(await store.ProcessDueAsync() == 3, "independent paid sources were not applied");
    var active = await store.SnapshotAsync();
    Ensure(active.Entitlements[$"{buyer}:premium-access"].Quantity == 4,
        "the derived aggregate did not sum two independent paid contributions");
    Ensure(active.EntitlementSources.Count(source => source.SubjectKey == buyer && source.GrantKey == "premium-access") == 2,
        "independent provider sources collapsed into one entitlement row");

    var refundAt = occurredAt.AddDays(10);
    await Deliver(store, catalog, Adjustment(
        "evt-combined-refund", "adjustment.updated", refundAt, "sim_adj_combined", recurringTransactionId, "approved"));
    Ensure(await store.ProcessDueAsync() == 1, "the recurring source refund was not projected");
    var refunded = await store.SnapshotAsync();
    var aggregate = refunded.Entitlements[$"{buyer}:premium-access"];
    Ensure(aggregate.Status == "active" && aggregate.Quantity == 2 && aggregate.EffectiveUntil is null,
        "refunding one provider source revoked an independent lifetime purchase");
    Ensure(refunded.Refunds is [{ TransactionId: recurringTransactionId, SubscriptionId: subscriptionId }],
        "the approved refund was not durably linked to its transaction and subscription");
    Ensure(!refunded.Evidence.Contains("immediate-refund"),
        "refund evidence was emitted before subscription cancellation converged");

    await Deliver(store, catalog, Transaction(
        "evt-combined-post-refund-before-cancel", "transaction.completed", refundAt.AddMilliseconds(1), buyer, "monthly",
        subscriptionId, "sim_txn_combined_post_refund", period));
    Ensure(await store.ProcessDueAsync() == 0,
        "a later recurring transaction reactivated a refunded subscription before cancellation");
    Ensure((await store.SnapshotAsync()).Events.Single(item => item.EventId == "evt-combined-post-refund-before-cancel").AttemptCount == 1,
        "the terminal refund fence did not reject the later recurring transaction");

    await Deliver(store, catalog, Subscription(
        "evt-combined-canceled", "subscription.canceled", refundAt.AddMilliseconds(2), buyer,
        subscriptionId, period, null, "canceled"));
    Ensure(await store.ProcessDueAsync() == 1, "subscription cancellation did not converge after refund");
    var converged = await store.SnapshotAsync();
    Ensure(converged.Evidence.Contains("immediate-refund"),
        "immediate-refund evidence was not emitted after refund and cancellation converged");
    Ensure(converged.Entitlements[$"{buyer}:premium-access"].Status == "active",
        "canceling the refunded subscription revoked an independent lifetime contribution");
    Ensure(converged.EntitlementSources
        .Where(source => source.SubjectKey == buyer)
        .Select(source => (source.SourceKey, source.Status))
        .OrderBy(source => source.SourceKey, StringComparer.Ordinal)
        .SequenceEqual(new[]
        {
            ("subscription:sim_sub_combined", "revoked"),
            ("transaction:sim_txn_combined_lifetime", "active")
        }), "the per-source terminal states are incorrect after convergence");

    await Deliver(store, catalog, Transaction(
        "evt-combined-late-old-transaction", "transaction.completed", occurredAt.AddDays(5), buyer, "monthly",
        subscriptionId, "sim_txn_combined_late_old", period));
    Ensure(await store.ProcessDueAsync() == 1, "a pre-refund late delivery was not consumed as stale");
    Ensure((await store.SnapshotAsync()).Events.Single(item => item.EventId == "evt-combined-late-old-transaction").IgnoredAsStale,
        "a pre-refund late delivery was not marked stale by the subscription-wide refund fence");

    await Deliver(store, catalog, Transaction(
        "evt-combined-resurrection", "transaction.completed", refundAt.AddMilliseconds(3), buyer, "monthly",
        subscriptionId, "sim_txn_combined_resurrection", period));
    Ensure(await store.ProcessDueAsync() == 0, "a post-cancellation transaction resurrected the refunded source");
    var final = await store.SnapshotAsync();
    Ensure(final.Events.Single(item => item.EventId == "evt-combined-resurrection").AttemptCount == 1,
        "the post-cancellation resurrection was not rejected durably");
    Ensure(await store.HasEntitlementAsync(buyer, "premium-access"),
        "the independent lifetime contribution was not available after selective revocation");
}

async Task TestOldPendingEventScope(
    string path,
    ProjectPaymentCatalog catalog,
    string oldScope,
    string replacementScope,
    DateTimeOffset occurredAt)
{
    var oldRuntime = new DurableProjectPaymentStore(path, catalog, oldScope, instanceId: "old-build-receiver");
    await new SimulatorProjectPaymentProvider(catalog, oldRuntime, TimeProvider.System).CreateCheckoutAsync("buyer-old-build", "lifetime");
    await Deliver(oldRuntime, catalog, Transaction(
        "evt-old-build-pending", "transaction.completed", occurredAt, "buyer-old-build", "lifetime", null,
        "sim_txn_old_build", null));

    var replacementRuntime = new DurableProjectPaymentStore(path, catalog, replacementScope, instanceId: "new-build-processor");
    Ensure(await replacementRuntime.ProcessDueAsync() == 0, "a replacement build processed an event normalized by the old build");
    var snapshot = await replacementRuntime.SnapshotAsync();
    Ensure(snapshot.Events.Single().AttemptCount == 1 && !snapshot.Events.Single().Processed,
        "an old-scope pending event was not rejected durably");
    Ensure(!snapshot.Entitlements.ContainsKey("buyer-old-build:premium-access"),
        "an old-scope pending event granted access in the replacement build");
}

async Task TestLegacyUnscopedEvidenceMigration(string path, ProjectPaymentCatalog catalog, string scope)
{
    await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
    {
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE project_payment_evidence(name TEXT PRIMARY KEY, observed_at TEXT NOT NULL);
            INSERT INTO project_payment_evidence(name,observed_at) VALUES('one-time-purchase','2026-08-08T00:00:00.0000000+00:00');
            """;
        await command.ExecuteNonQueryAsync();
    }
    var migrated = new DurableProjectPaymentStore(path, catalog, scope, instanceId: "legacy-evidence-migration");
    var status = await migrated.VerificationStatusAsync(scope);
    Ensure(!status.LifecyclePassed && !status.RestartReplayPassed,
        "legacy unscoped lifecycle evidence survived the exact-build scope migration");
    Ensure((await migrated.SnapshotAsync()).Evidence.Count == 0,
        "legacy unscoped evidence was attributed to the current exact build");
}

async Task TestLegacyEntitlementContributionMigration(string path, ProjectPaymentCatalog catalog, string scope)
{
    await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
    {
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE project_payment_entitlement (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              subject_key TEXT NOT NULL,
              grant_key TEXT NOT NULL,
              quantity INTEGER NOT NULL,
              status TEXT NOT NULL,
              effective_from TEXT NOT NULL,
              effective_until TEXT NULL,
              billing_period_start TEXT NULL,
              billing_period_end TEXT NULL,
              source_price_id TEXT NOT NULL,
              source_event_id TEXT NOT NULL,
              last_occurred_at TEXT NOT NULL,
              UNIQUE(subject_key,grant_key)
            );
            INSERT INTO project_payment_entitlement(
              subject_key,grant_key,quantity,status,effective_from,effective_until,
              billing_period_start,billing_period_end,source_price_id,source_event_id,last_occurred_at)
            VALUES('buyer-legacy','premium-access',2,'active','2026-08-01T00:00:00.0000000+00:00',NULL,
                   NULL,NULL,'sim_price_lifetime','evt-legacy','2026-08-01T00:00:00.0000000+00:00');
            """;
        await command.ExecuteNonQueryAsync();
    }

    var migrated = new DurableProjectPaymentStore(path, catalog, scope, instanceId: "legacy-entitlement-migration");
    var snapshot = await migrated.SnapshotAsync();
    Ensure(snapshot.EntitlementSources is [{ SourceKey: "legacy:1", SubjectKey: "buyer-legacy", Status: "active" }],
        "the legacy aggregate was not conservatively backfilled as a durable source contribution");
    Ensure(await migrated.HasEntitlementAsync("buyer-legacy", "premium-access"),
        "the source-contribution migration silently revoked legacy access");
}

async Task<bool> Deliver(DurableProjectPaymentStore store, ProjectPaymentCatalog catalog, System.Text.Json.Nodes.JsonObject payload)
{
    var raw = JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    var now = DateTimeOffset.UtcNow;
    var signature = ProjectPaymentSignature.Sign(raw, secret, now);
    Ensure(ProjectPaymentSignature.Verify(raw, signature, secret, now), "generated signed delivery did not verify");
    var normalized = await ProjectPaymentProtocol.NormalizeVerifiedEventAsync(raw, environmentId, catalog, store);
    return await store.InsertVerifiedEventAsync(normalized);
}

async Task NormalizeOnly(DurableProjectPaymentStore store, ProjectPaymentCatalog catalog, System.Text.Json.Nodes.JsonObject payload)
{
    var raw = JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web));
    _ = await ProjectPaymentProtocol.NormalizeVerifiedEventAsync(raw, environmentId, catalog, store);
}

static System.Text.Json.Nodes.JsonObject Transaction(
    string eventId, string eventType, DateTimeOffset occurredAt, string buyer, string priceKey,
    string? subscriptionId, string transactionId, PeriodWindow? period, string? status = null)
{
    var recurring = priceKey == "monthly";
    var amount = recurring ? 1500 : 9900;
    var priceId = recurring ? "sim_price_monthly" : "sim_price_lifetime";
    return Envelope(eventId, eventType, occurredAt, new()
    {
        ["id"] = transactionId,
        ["status"] = status ?? "completed",
        ["customer_id"] = buyer,
        ["subscription_id"] = subscriptionId,
        ["items"] = new System.Text.Json.Nodes.JsonArray(new System.Text.Json.Nodes.JsonObject
        {
            ["price_id"] = priceId,
            ["product_id"] = "sim_prod_pro",
            ["quantity"] = 1,
            ["billing_period"] = period is null ? null : BillingPeriod(period)
        }),
        ["details"] = new System.Text.Json.Nodes.JsonObject
        {
            ["totals"] = new System.Text.Json.Nodes.JsonObject { ["total"] = amount.ToString(), ["currency_code"] = "USD" }
        },
        ["custom_data"] = EnvironmentData()
    });
}

static System.Text.Json.Nodes.JsonObject Subscription(
    string eventId, string eventType, DateTimeOffset occurredAt, string buyer, string subscriptionId,
    PeriodWindow period, DateTimeOffset? scheduledAt, string? status = null) => Envelope(eventId, eventType, occurredAt, new()
    {
        ["id"] = subscriptionId,
        ["status"] = status ?? "active",
        ["customer_id"] = buyer,
        ["items"] = new System.Text.Json.Nodes.JsonArray(new System.Text.Json.Nodes.JsonObject
        {
            ["price_id"] = "sim_price_monthly",
            ["product_id"] = "sim_prod_pro",
            ["quantity"] = 1
        }),
        ["current_billing_period"] = BillingPeriod(period),
        ["scheduled_change"] = scheduledAt is null ? null : new System.Text.Json.Nodes.JsonObject { ["action"] = "cancel", ["effective_at"] = scheduledAt.Value },
        ["custom_data"] = EnvironmentData()
    });

static System.Text.Json.Nodes.JsonObject Adjustment(
    string eventId, string eventType, DateTimeOffset occurredAt, string adjustmentId, string transactionId, string status) => Envelope(eventId, eventType, occurredAt, new()
    {
        ["id"] = adjustmentId,
        ["action"] = "refund",
        ["status"] = status,
        ["transaction_id"] = transactionId,
        ["totals"] = new System.Text.Json.Nodes.JsonObject { ["total"] = "1500", ["currency_code"] = "USD" },
        ["custom_data"] = EnvironmentData()
    });

static System.Text.Json.Nodes.JsonObject Envelope(string eventId, string eventType, DateTimeOffset occurredAt, System.Text.Json.Nodes.JsonObject data) => new()
{
    ["event_id"] = eventId,
    ["event_type"] = eventType,
    ["occurred_at"] = occurredAt,
    ["notification_id"] = $"sim_ntf_{eventId}",
    ["data"] = data
};

static System.Text.Json.Nodes.JsonObject BillingPeriod(PeriodWindow period) => new()
{
    ["starts_at"] = period.StartsAt,
    ["ends_at"] = period.EndsAt
};

static System.Text.Json.Nodes.JsonObject EnvironmentData() => new() { ["vibenest_environment_id"] = environmentId };
static PeriodWindow Period(DateTimeOffset startsAt, DateTimeOffset endsAt) => new(startsAt, endsAt);

static object CatalogProjection(string environment, string manifestDigest) => new
{
    provider = "simulator",
    sellerExternalId = "sim_seller_fixture",
    environmentExternalId = environment,
    manifestDigest,
    products = new[]
    {
        new
        {
            manifestKey = "pro",
            externalId = "sim_prod_pro",
            prices = new object[]
            {
                new { manifestKey = "monthly", externalId = "sim_price_monthly", currency = "USD", unitAmount = 1500, type = "recurring", interval = "month" },
                new { manifestKey = "lifetime", externalId = "sim_price_lifetime", currency = "USD", unitAmount = 9900, type = "one_time", interval = (string?)null }
            },
            grants = new[] { new { entitlement = "premium-access", quantity = 2 } }
        }
    }
};

static string EncodeCatalog(object projection) => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(projection, new JsonSerializerOptions(JsonSerializerDefaults.Web)));

static void Ensure(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void MustThrow(Action action)
{
    try { action(); }
    catch (InvalidOperationException) { return; }
    throw new InvalidOperationException("Expected fail-closed exception.");
}

static async Task MustThrowAsync(Func<Task> action)
{
    try { await action(); }
    catch (InvalidOperationException) { return; }
    throw new InvalidOperationException("Expected fail-closed exception.");
}

file sealed record PeriodWindow(DateTimeOffset StartsAt, DateTimeOffset EndsAt);

file sealed class ChunkedReadStream(byte[] bytes, int maxChunkSize) : Stream
{
    private int _offset;

    public int BytesRead => _offset;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) =>
        Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        var count = Math.Min(Math.Min(buffer.Length, maxChunkSize), bytes.Length - _offset);
        if (count <= 0) return 0;
        bytes.AsSpan(_offset, count).CopyTo(buffer);
        _offset += count;
        return count;
    }

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(Read(buffer.Span));
    }

    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
