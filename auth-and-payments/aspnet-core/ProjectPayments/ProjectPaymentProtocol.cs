using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace Fixture.ProjectPayments;

public static class ProjectPaymentProtocol
{
    public static async Task<NormalizedProjectPaymentEvent> NormalizeVerifiedEventAsync(
        ReadOnlyMemory<byte> rawBody,
        string destinationKey,
        ProjectPaymentCatalog catalog,
        DurableProjectPaymentStore store,
        CancellationToken cancellationToken = default)
    {
        if (rawBody.IsEmpty || rawBody.Length > 1024 * 1024) throw new InvalidSimulatorEventException("The signed simulator event body is empty or too large.");
        ProjectPaymentSecurity.RequireIdentifier(destinationKey, "Destination key");
        if (!ProjectPaymentSecurity.ConstantText(destinationKey, catalog.EnvironmentExternalId))
            throw new InvalidSimulatorEventException("The signed simulator event targets a different destination.");

        JsonDocument document;
        try { document = JsonDocument.Parse(rawBody, new JsonDocumentOptions { MaxDepth = 12 }); }
        catch (JsonException) { throw new InvalidSimulatorEventException("The signed simulator event is not valid JSON."); }
        using (document)
        {
            var root = document.RootElement;
            RequireObject(root, ["event_id", "event_type", "occurred_at", "notification_id", "data"], "event envelope");
            var eventId = RequiredIdentifier(root, "event_id", "Event id");
            _ = RequiredIdentifier(root, "notification_id", "Notification id");
            var eventType = RequiredString(root, "event_type");
            var occurredAt = RequiredDate(root, "occurred_at");
            var data = root.GetProperty("data");
            var digest = Convert.ToHexStringLower(SHA256.HashData(rawBody.Span));
            return eventType switch
            {
                "transaction.completed" => await NormalizeTransactionAsync(destinationKey, eventId, eventType, occurredAt, digest, data, "completed", catalog, store, cancellationToken),
                "transaction.payment_failed" => await NormalizeTransactionAsync(destinationKey, eventId, eventType, occurredAt, digest, data, "declined", catalog, store, cancellationToken),
                "subscription.created" => await NormalizeSubscriptionAsync(destinationKey, eventId, eventType, occurredAt, digest, data, "active", catalog, store, cancellationToken),
                "subscription.updated" => await NormalizeSubscriptionAsync(destinationKey, eventId, eventType, occurredAt, digest, data, "active", catalog, store, cancellationToken),
                "subscription.canceled" => await NormalizeSubscriptionAsync(destinationKey, eventId, eventType, occurredAt, digest, data, "canceled", catalog, store, cancellationToken),
                "adjustment.created" => NormalizeAdjustment(destinationKey, eventId, eventType, occurredAt, digest, store.EvidenceScope, data, "pending_approval", catalog),
                "adjustment.updated" => NormalizeAdjustment(destinationKey, eventId, eventType, occurredAt, digest, store.EvidenceScope, data, "approved", catalog),
                "customer.portal_session.created" => await NormalizePortalAsync(destinationKey, eventId, eventType, occurredAt, digest, data, catalog, store, cancellationToken),
                _ => throw new InvalidSimulatorEventException("The signed simulator event type is unsupported.")
            };
        }
    }

    private static async Task<NormalizedProjectPaymentEvent> NormalizeTransactionAsync(
        string destinationKey,
        string eventId,
        string eventType,
        DateTimeOffset occurredAt,
        string digest,
        JsonElement data,
        string expectedStatus,
        ProjectPaymentCatalog catalog,
        DurableProjectPaymentStore store,
        CancellationToken cancellationToken)
    {
        RequireObject(data, ["id", "status", "customer_id", "subscription_id", "items", "details", "custom_data"], "transaction data");
        var transactionId = RequiredIdentifier(data, "id", "Transaction id");
        var status = RequiredString(data, "status");
        if (status != expectedStatus) throw new InvalidSimulatorEventException("The transaction status is incompatible with its event type.");
        var customerId = RequiredIdentifier(data, "customer_id", "Provider customer id");
        var subject = await store.ResolveSubjectAsync(customerId, cancellationToken)
            ?? throw new InvalidSimulatorEventException("The signed transaction does not belong to a server-authenticated buyer binding.");
        string? subscriptionId = null;
        var subscriptionElement = data.GetProperty("subscription_id");
        if (subscriptionElement.ValueKind != JsonValueKind.Null)
            subscriptionId = RequiredIdentifier(data, "subscription_id", "Subscription id");

        var item = SingleArrayItem(data, "items", "transaction items");
        RequireObject(item, ["price_id", "product_id", "quantity", "billing_period"], "transaction item");
        var productId = RequiredIdentifier(item, "product_id", "Provider product id");
        var priceId = RequiredIdentifier(item, "price_id", "Provider price id");
        var price = catalog.ResolveByExternalIds(productId, priceId);
        RequireQuantityOne(item);
        var (periodStart, periodEnd) = ParseBillingPeriod(item.GetProperty("billing_period"), price);

        var details = data.GetProperty("details");
        RequireObject(details, ["totals"], "transaction details");
        var (amount, currency) = ParseTotals(details.GetProperty("totals"));
        if (amount != price.UnitAmount || currency != price.Currency)
            throw new InvalidSimulatorEventException("The signed transaction totals do not match the trusted runtime price.");
        RequireEnvironment(data.GetProperty("custom_data"), catalog.EnvironmentExternalId);
        if (price.Type == "one_time" && subscriptionId is not null)
            throw new InvalidSimulatorEventException("A one-time transaction cannot reference a subscription.");
        if (price.Type == "recurring" && subscriptionId is null && eventType == "transaction.completed")
            throw new InvalidSimulatorEventException("A completed recurring transaction must reference a subscription.");

        return new(destinationKey, eventId, eventType, occurredAt, digest, store.EvidenceScope, subject, customerId, transactionId,
            subscriptionId, productId, priceId, status, amount, currency, periodStart, periodEnd, null);
    }

    private static async Task<NormalizedProjectPaymentEvent> NormalizeSubscriptionAsync(
        string destinationKey,
        string eventId,
        string eventType,
        DateTimeOffset occurredAt,
        string digest,
        JsonElement data,
        string expectedStatus,
        ProjectPaymentCatalog catalog,
        DurableProjectPaymentStore store,
        CancellationToken cancellationToken)
    {
        RequireObject(data, ["id", "status", "customer_id", "items", "current_billing_period", "scheduled_change", "custom_data"], "subscription data");
        var subscriptionId = RequiredIdentifier(data, "id", "Subscription id");
        var status = RequiredString(data, "status");
        if (status != expectedStatus) throw new InvalidSimulatorEventException("The subscription status is incompatible with its event type.");
        var customerId = RequiredIdentifier(data, "customer_id", "Provider customer id");
        var subject = await store.ResolveSubjectAsync(customerId, cancellationToken)
            ?? throw new InvalidSimulatorEventException("The signed subscription does not belong to a server-authenticated buyer binding.");
        var item = SingleArrayItem(data, "items", "subscription items");
        RequireObject(item, ["price_id", "product_id", "quantity"], "subscription item");
        var productId = RequiredIdentifier(item, "product_id", "Provider product id");
        var priceId = RequiredIdentifier(item, "price_id", "Provider price id");
        var price = catalog.ResolveByExternalIds(productId, priceId);
        if (price.Type != "recurring") throw new InvalidSimulatorEventException("A subscription must use a trusted recurring price.");
        RequireQuantityOne(item);
        var (periodStart, periodEnd) = ParseBillingPeriod(data.GetProperty("current_billing_period"), price);
        if (periodStart is null || periodEnd is null) throw new InvalidSimulatorEventException("A subscription requires an authoritative billing period.");

        DateTimeOffset? scheduledChangeAt = null;
        var scheduled = data.GetProperty("scheduled_change");
        if (scheduled.ValueKind != JsonValueKind.Null)
        {
            RequireObject(scheduled, ["action", "effective_at"], "scheduled change");
            if (RequiredString(scheduled, "action") != "cancel") throw new InvalidSimulatorEventException("Only scheduled cancellation is supported.");
            scheduledChangeAt = RequiredDate(scheduled, "effective_at");
            if (eventType != "subscription.updated" || scheduledChangeAt != periodEnd)
                throw new InvalidSimulatorEventException("A scheduled cancellation must be effective at the signed period end.");
        }
        if (eventType != "subscription.updated" && scheduled.ValueKind != JsonValueKind.Null)
            throw new InvalidSimulatorEventException("This subscription event cannot contain a scheduled change.");
        RequireEnvironment(data.GetProperty("custom_data"), catalog.EnvironmentExternalId);
        return new(destinationKey, eventId, eventType, occurredAt, digest, store.EvidenceScope, subject, customerId, null,
            subscriptionId, productId, priceId, status, null, null, periodStart, periodEnd, scheduledChangeAt);
    }

    private static NormalizedProjectPaymentEvent NormalizeAdjustment(
        string destinationKey,
        string eventId,
        string eventType,
        DateTimeOffset occurredAt,
        string digest,
        string evidenceScope,
        JsonElement data,
        string expectedStatus,
        ProjectPaymentCatalog catalog)
    {
        RequireObject(data, ["id", "action", "status", "transaction_id", "totals", "custom_data"], "adjustment data");
        _ = RequiredIdentifier(data, "id", "Adjustment id");
        if (RequiredString(data, "action") != "refund" || RequiredString(data, "status") != expectedStatus)
            throw new InvalidSimulatorEventException("The adjustment action or status is incompatible with its event type.");
        var transactionId = RequiredIdentifier(data, "transaction_id", "Adjusted transaction id");
        var (amount, currency) = ParseTotals(data.GetProperty("totals"));
        RequireEnvironment(data.GetProperty("custom_data"), catalog.EnvironmentExternalId);
        return new(destinationKey, eventId, eventType, occurredAt, digest, evidenceScope, null, null, transactionId,
            null, null, null, expectedStatus, amount, currency, null, null, null);
    }

    private static async Task<NormalizedProjectPaymentEvent> NormalizePortalAsync(
        string destinationKey,
        string eventId,
        string eventType,
        DateTimeOffset occurredAt,
        string digest,
        JsonElement data,
        ProjectPaymentCatalog catalog,
        DurableProjectPaymentStore store,
        CancellationToken cancellationToken)
    {
        RequireObject(data, ["id", "customer_id", "url", "expires_at", "custom_data"], "portal session data");
        _ = RequiredIdentifier(data, "id", "Portal session id");
        var customerId = RequiredIdentifier(data, "customer_id", "Provider customer id");
        var subject = await store.ResolveSubjectAsync(customerId, cancellationToken)
            ?? throw new InvalidSimulatorEventException("The signed portal session does not belong to a server-authenticated buyer binding.");
        if (!Uri.TryCreate(RequiredString(data, "url"), UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps || url.Host != "simulator.invalid")
            throw new InvalidSimulatorEventException("The simulator portal URL is invalid.");
        _ = RequiredDate(data, "expires_at");
        RequireEnvironment(data.GetProperty("custom_data"), catalog.EnvironmentExternalId);
        return new(destinationKey, eventId, eventType, occurredAt, digest, store.EvidenceScope, subject, customerId, null,
            null, null, null, "created", null, null, null, null, null);
    }

    private static (DateTimeOffset? Start, DateTimeOffset? End) ParseBillingPeriod(JsonElement element, ProjectPaymentPrice price)
    {
        if (price.Type == "one_time")
        {
            if (element.ValueKind != JsonValueKind.Null) throw new InvalidSimulatorEventException("A one-time item cannot contain a billing period.");
            return (null, null);
        }
        RequireObject(element, ["starts_at", "ends_at"], "billing period");
        var startsAt = RequiredDate(element, "starts_at");
        var endsAt = RequiredDate(element, "ends_at");
        var expectedEnd = price.Interval switch
        {
            "month" => startsAt.AddMonths(1),
            "year" => startsAt.AddYears(1),
            _ => throw new InvalidSimulatorEventException("The trusted recurring interval is invalid.")
        };
        if (endsAt != expectedEnd) throw new InvalidSimulatorEventException("The signed billing period does not match the trusted catalog interval.");
        return (startsAt, endsAt);
    }

    private static (long Amount, string Currency) ParseTotals(JsonElement totals)
    {
        RequireObject(totals, ["total", "currency_code"], "totals");
        var total = RequiredString(totals, "total");
        var currency = RequiredString(totals, "currency_code");
        if (!long.TryParse(total, NumberStyles.None, CultureInfo.InvariantCulture, out var amount) || amount <= 0
            || currency.Length != 3 || currency.Any(value => value is < 'A' or > 'Z'))
            throw new InvalidSimulatorEventException("The signed totals are invalid.");
        return (amount, currency);
    }

    private static void RequireEnvironment(JsonElement customData, string environmentId)
    {
        RequireObject(customData, ["vibenest_environment_id"], "custom data");
        if (!ProjectPaymentSecurity.ConstantText(RequiredString(customData, "vibenest_environment_id"), environmentId))
            throw new InvalidSimulatorEventException("The signed event targets a different simulator environment.");
    }

    private static void RequireQuantityOne(JsonElement item)
    {
        var quantity = item.GetProperty("quantity");
        if (!quantity.TryGetInt32(out var value) || value != 1)
            throw new InvalidSimulatorEventException("The fixture accepts exactly one trusted catalog item per event.");
    }

    private static JsonElement SingleArrayItem(JsonElement parent, string property, string label)
    {
        var array = parent.GetProperty(property);
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() != 1)
            throw new InvalidSimulatorEventException($"The {label} must contain exactly one item.");
        return array[0];
    }

    private static void RequireObject(JsonElement element, IReadOnlyCollection<string> exactProperties, string label)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidSimulatorEventException($"The {label} must be an object.");
        var names = element.EnumerateObject().Select(item => item.Name).ToArray();
        if (names.Length != exactProperties.Count || names.Distinct(StringComparer.Ordinal).Count() != names.Length
            || names.Any(name => !exactProperties.Contains(name, StringComparer.Ordinal)))
            throw new InvalidSimulatorEventException($"The {label} has an unexpected or duplicate property.");
    }

    private static string RequiredString(JsonElement parent, string property)
    {
        var element = parent.GetProperty(property);
        return element.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(element.GetString())
            ? element.GetString()!
            : throw new InvalidSimulatorEventException($"Event property '{property}' must be a non-empty string.");
    }

    private static string RequiredIdentifier(JsonElement parent, string property, string label)
    {
        var value = RequiredString(parent, property);
        try { ProjectPaymentSecurity.RequireIdentifier(value, label); }
        catch (InvalidOperationException exception) { throw new InvalidSimulatorEventException(exception.Message); }
        return value;
    }

    private static DateTimeOffset RequiredDate(JsonElement parent, string property)
    {
        var value = RequiredString(parent, property);
        if (!DateTimeOffset.TryParseExact(value, ["O", "yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"], CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
            throw new InvalidSimulatorEventException($"Event property '{property}' must be an ISO-8601 timestamp.");
        return parsed;
    }
}
