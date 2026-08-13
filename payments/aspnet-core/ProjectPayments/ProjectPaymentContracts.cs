using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Fixture.ProjectPayments;

public enum ProjectPaymentProviderMode
{
    Simulator,
    Paddle,
    Disabled
}

public sealed record ProjectPaymentRuntimeConfiguration(
    ProjectPaymentProviderMode Provider,
    bool PaymentsEnabled,
    bool VerifierEnabled,
    string WebhookSecret,
    string BuiltCommitSha,
    string ManifestDigest,
    string EnvironmentId,
    string CatalogBase64)
{
    public static ProjectPaymentRuntimeConfiguration From(IConfiguration configuration)
    {
        var sourceCommit = configuration["SOURCE_COMMIT"];
        var legacyCommit = configuration["VIBENEST_BUILD_COMMIT_SHA"];
        return new(
            configuration["VIBENEST_PROJECT_PAYMENTS_PROVIDER"]?.Trim().ToLowerInvariant() switch
            {
                "simulator" => ProjectPaymentProviderMode.Simulator,
                "paddle" => ProjectPaymentProviderMode.Paddle,
                _ => ProjectPaymentProviderMode.Disabled
            },
            string.Equals(configuration["VIBENEST_PROJECT_PAYMENTS_ENABLED"], "true", StringComparison.OrdinalIgnoreCase),
            string.Equals(configuration["VIBENEST_PROJECT_PAYMENTS_VERIFIER_ENABLED"], "true", StringComparison.OrdinalIgnoreCase),
            configuration["VIBENEST_PROJECT_PAYMENTS_WEBHOOK_SECRET"] ?? string.Empty,
            !string.IsNullOrWhiteSpace(sourceCommit) ? sourceCommit.Trim() : legacyCommit?.Trim() ?? string.Empty,
            configuration["VIBENEST_PROJECT_PAYMENTS_MANIFEST_DIGEST"]?.Trim() ?? string.Empty,
            configuration["VIBENEST_PROJECT_PAYMENTS_ENVIRONMENT_ID"]?.Trim() ?? string.Empty,
            configuration["VIBENEST_PROJECT_PAYMENTS_CATALOG_B64"] ?? string.Empty);
    }

    public ProjectPaymentCatalog LoadCatalog()
    {
        if (!PaymentsEnabled || Provider != ProjectPaymentProviderMode.Simulator)
            throw new InvalidOperationException("The simulator catalog is unavailable while project payments are disabled.");
        if (!ProjectPaymentSecurity.HasStrongSecret(WebhookSecret))
            throw new InvalidOperationException("The simulator webhook secret must contain at least 256 bits.");
        return ProjectPaymentCatalog.Parse(CatalogBase64, EnvironmentId, ManifestDigest);
    }

    public string EvidenceScope => ProjectPaymentEvidenceScope.Compute(EnvironmentId, ManifestDigest, BuiltCommitSha);
}

public static class ProjectPaymentEvidenceScope
{
    public static string Compute(string environmentId, string manifestDigest, string builtCommit)
    {
        ProjectPaymentSecurity.RequireIdentifier(environmentId, "Evidence environment id");
        if (manifestDigest.Length != 64 || manifestDigest.Any(value => value is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidOperationException("The evidence manifest digest is invalid.");
        if (builtCommit.Length != 40 || builtCommit.Any(value => value is not (>= '0' and <= '9') and not (>= 'a' and <= 'f')))
            throw new InvalidOperationException("The evidence build commit is invalid.");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.UTF8.GetBytes("vibenest-project-payments-evidence-v1\0"));
        hash.AppendData(Encoding.UTF8.GetBytes(environmentId));
        hash.AppendData([0]);
        hash.AppendData(Encoding.ASCII.GetBytes(manifestDigest));
        hash.AppendData([0]);
        hash.AppendData(Encoding.ASCII.GetBytes(builtCommit));
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}

public sealed record ProjectPaymentGrant(string Entitlement, int Quantity);

public sealed record ProjectPaymentPrice(
    string ManifestKey,
    string ExternalId,
    string Currency,
    long UnitAmount,
    string Type,
    string? Interval,
    string ProductManifestKey,
    string ProductExternalId,
    IReadOnlyList<ProjectPaymentGrant> Grants);

public sealed class ProjectPaymentCatalog
{
    private const int MaximumEncodedBytes = 65_536;
    private const int MaximumDecodedBytes = 48 * 1024;
    private static readonly Regex IdentifierPattern = new("^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$", RegexOptions.CultureInvariant);
    private static readonly Regex DigestPattern = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);
    private static readonly Regex CurrencyPattern = new("^[A-Z]{3}$", RegexOptions.CultureInvariant);
    private readonly IReadOnlyList<ProjectPaymentPrice> _prices;

    private ProjectPaymentCatalog(
        string sellerExternalId,
        string environmentExternalId,
        string manifestDigest,
        IReadOnlyList<ProjectPaymentPrice> prices)
    {
        SellerExternalId = sellerExternalId;
        EnvironmentExternalId = environmentExternalId;
        ManifestDigest = manifestDigest;
        _prices = prices;
    }

    public string SellerExternalId { get; }
    public string EnvironmentExternalId { get; }
    public string ManifestDigest { get; }
    public IReadOnlyList<ProjectPaymentPrice> Prices => _prices;

    public ProjectPaymentPrice ResolveByManifestKey(string priceKey)
    {
        ProjectPaymentSecurity.RequireIdentifier(priceKey, "Price key");
        var matches = _prices.Where(item => item.ManifestKey == priceKey).Take(2).ToArray();
        return matches.Length == 1
            ? matches[0]
            : throw new InvalidOperationException("The requested price key is missing or ambiguous in the trusted runtime catalog.");
    }

    public ProjectPaymentPrice ResolveByExternalIds(string productId, string priceId)
    {
        ProjectPaymentSecurity.RequireIdentifier(productId, "Provider product id");
        ProjectPaymentSecurity.RequireIdentifier(priceId, "Provider price id");
        return _prices.SingleOrDefault(item => item.ProductExternalId == productId && item.ExternalId == priceId)
            ?? throw new InvalidSimulatorEventException("The signed event references an unmapped product or price.");
    }

    public static ProjectPaymentCatalog Parse(string encoded, string expectedEnvironmentId, string expectedManifestDigest)
    {
        ProjectPaymentSecurity.RequireIdentifier(expectedEnvironmentId, "Expected environment id");
        if (!DigestPattern.IsMatch(expectedManifestDigest))
            throw new InvalidOperationException("The installed manifest digest is invalid.");
        if (string.IsNullOrEmpty(encoded) || encoded.Length > MaximumEncodedBytes || encoded.Length % 4 != 0)
            throw new InvalidOperationException("The simulator runtime catalog must be bounded canonical RFC4648 base64.");

        byte[] bytes;
        try { bytes = Convert.FromBase64String(encoded); }
        catch (FormatException) { throw new InvalidOperationException("The simulator runtime catalog is not valid RFC4648 base64."); }
        if (bytes.Length == 0 || bytes.Length > MaximumDecodedBytes || !ProjectPaymentSecurity.ConstantText(Convert.ToBase64String(bytes), encoded))
            throw new InvalidOperationException("The simulator runtime catalog is non-canonical or exceeds the runtime limit.");

        string json;
        try { json = new UTF8Encoding(false, true).GetString(bytes); }
        catch (DecoderFallbackException) { throw new InvalidOperationException("The simulator runtime catalog is not valid UTF-8."); }

        JsonDocument document;
        try { document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 }); }
        catch (JsonException) { throw new InvalidOperationException("The simulator runtime catalog is not valid JSON."); }
        using (document)
        {
            var root = document.RootElement;
            RequireObject(root, ["provider", "sellerExternalId", "environmentExternalId", "manifestDigest", "products"], "runtime catalog");
            if (RequiredString(root, "provider") != "simulator")
                throw new InvalidOperationException("The runtime catalog is not a simulator catalog.");
            var sellerId = RequiredIdentifier(root, "sellerExternalId", "Runtime seller id");
            var environmentId = RequiredIdentifier(root, "environmentExternalId", "Runtime environment id");
            var digest = RequiredString(root, "manifestDigest");
            if (!ProjectPaymentSecurity.ConstantText(environmentId, expectedEnvironmentId))
                throw new InvalidOperationException("The runtime catalog targets a different seller environment.");
            if (!DigestPattern.IsMatch(digest) || !ProjectPaymentSecurity.ConstantText(digest, expectedManifestDigest))
                throw new InvalidOperationException("The runtime catalog manifest digest does not match the installed manifest.");

            var products = RequiredArray(root, "products", 1, 100, "products");
            var productKeys = new HashSet<string>(StringComparer.Ordinal);
            var productIds = new HashSet<string>(StringComparer.Ordinal);
            var globalPriceIds = new HashSet<string>(StringComparer.Ordinal);
            var prices = new List<ProjectPaymentPrice>();
            foreach (var product in products.EnumerateArray())
            {
                RequireObject(product, ["manifestKey", "externalId", "prices", "grants"], "runtime product");
                var productKey = RequiredIdentifier(product, "manifestKey", "Runtime product key");
                var productId = RequiredIdentifier(product, "externalId", "Runtime product external id");
                if (!productKeys.Add(productKey) || !productIds.Add(productId))
                    throw new InvalidOperationException("Runtime product keys and external ids must be unique.");

                var grantElements = RequiredArray(product, "grants", 1, 100, "product grants");
                var grantKeys = new HashSet<string>(StringComparer.Ordinal);
                var grants = new List<ProjectPaymentGrant>();
                foreach (var grant in grantElements.EnumerateArray())
                {
                    RequireObject(grant, ["entitlement", "quantity"], "runtime grant");
                    var entitlement = RequiredIdentifier(grant, "entitlement", "Runtime grant entitlement");
                    var quantityElement = grant.GetProperty("quantity");
                    if (!quantityElement.TryGetInt32(out var quantity) || quantity <= 0 || !grantKeys.Add(entitlement))
                        throw new InvalidOperationException("Runtime grant entitlements must be unique and quantities must be positive integers.");
                    grants.Add(new(entitlement, quantity));
                }

                var priceElements = RequiredArray(product, "prices", 1, 100, "product prices");
                var priceKeys = new HashSet<string>(StringComparer.Ordinal);
                foreach (var price in priceElements.EnumerateArray())
                {
                    RequireObject(price, ["manifestKey", "externalId", "currency", "unitAmount", "type", "interval"], "runtime price");
                    var priceKey = RequiredIdentifier(price, "manifestKey", "Runtime price key");
                    var priceId = RequiredIdentifier(price, "externalId", "Runtime price external id");
                    var currency = RequiredString(price, "currency");
                    var type = RequiredString(price, "type");
                    var amountElement = price.GetProperty("unitAmount");
                    var intervalElement = price.GetProperty("interval");
                    var interval = intervalElement.ValueKind == JsonValueKind.Null ? null : intervalElement.GetString();
                    if (!priceKeys.Add(priceKey) || !globalPriceIds.Add(priceId))
                        throw new InvalidOperationException("Runtime price keys within a product and external ids globally must be unique.");
                    if (!CurrencyPattern.IsMatch(currency) || !amountElement.TryGetInt64(out var amount) || amount <= 0)
                        throw new InvalidOperationException("Runtime price currency and amount are invalid.");
                    if (type == "one_time" ? interval is not null : type != "recurring" || interval is not ("month" or "year"))
                        throw new InvalidOperationException("Runtime price type and interval are inconsistent.");
                    prices.Add(new(priceKey, priceId, currency, amount, type, interval, productKey, productId, grants.ToArray()));
                }
            }
            return new(sellerId, environmentId, digest, prices.ToArray());
        }
    }

    private static void RequireObject(JsonElement element, IReadOnlyCollection<string> exactProperties, string label)
    {
        if (element.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException($"The {label} must be an object.");
        var names = element.EnumerateObject().Select(item => item.Name).ToArray();
        if (names.Length != exactProperties.Count || names.Distinct(StringComparer.Ordinal).Count() != names.Length
            || names.Any(name => !exactProperties.Contains(name, StringComparer.Ordinal)))
            throw new InvalidOperationException($"The {label} has an unexpected or duplicate property.");
    }

    private static string RequiredString(JsonElement parent, string property)
    {
        var element = parent.GetProperty(property);
        return element.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(element.GetString())
            ? element.GetString()!
            : throw new InvalidOperationException($"Runtime catalog property '{property}' must be a non-empty string.");
    }

    private static string RequiredIdentifier(JsonElement parent, string property, string label)
    {
        var value = RequiredString(parent, property);
        if (!IdentifierPattern.IsMatch(value)) throw new InvalidOperationException($"{label} is invalid.");
        return value;
    }

    private static JsonElement RequiredArray(JsonElement parent, string property, int minimum, int maximum, string label)
    {
        var element = parent.GetProperty(property);
        if (element.ValueKind != JsonValueKind.Array || element.GetArrayLength() < minimum || element.GetArrayLength() > maximum)
            throw new InvalidOperationException($"Runtime catalog {label} must be a bounded non-empty array.");
        return element;
    }
}

public interface IProjectPaymentProvider
{
    ProjectPaymentProviderMode Mode { get; }
    Task<IReadOnlyList<PricePreview>> PreviewPricesAsync(IReadOnlyList<string> priceKeys, CancellationToken cancellationToken = default);
    Task<CheckoutSession> CreateCheckoutAsync(string buyerKey, string priceKey, CancellationToken cancellationToken = default);
    Task<PortalSession> CreatePortalAsync(string buyerKey, CancellationToken cancellationToken = default);
}

public sealed record PricePreview(string PriceKey, long UnitAmount, string Currency, string Type, string? Interval, string Formatted);
public sealed record CheckoutSession(string Id, DateTimeOffset ExpiresAt);
public sealed record PortalSession(Uri Url, DateTimeOffset ExpiresAt);

public sealed class DisabledProjectPaymentProvider : IProjectPaymentProvider
{
    public ProjectPaymentProviderMode Mode => ProjectPaymentProviderMode.Disabled;
    public Task<IReadOnlyList<PricePreview>> PreviewPricesAsync(IReadOnlyList<string> priceKeys, CancellationToken cancellationToken = default) =>
        Task.FromException<IReadOnlyList<PricePreview>>(Disabled());
    public Task<CheckoutSession> CreateCheckoutAsync(string buyerKey, string priceKey, CancellationToken cancellationToken = default) =>
        Task.FromException<CheckoutSession>(Disabled());
    public Task<PortalSession> CreatePortalAsync(string buyerKey, CancellationToken cancellationToken = default) =>
        Task.FromException<PortalSession>(Disabled());
    private static InvalidOperationException Disabled() => new("Project payments are disabled.");
}

public sealed class SimulatorProjectPaymentProvider(ProjectPaymentCatalog catalog, DurableProjectPaymentStore store, TimeProvider timeProvider) : IProjectPaymentProvider
{
    public ProjectPaymentProviderMode Mode => ProjectPaymentProviderMode.Simulator;

    public async Task<IReadOnlyList<PricePreview>> PreviewPricesAsync(IReadOnlyList<string> priceKeys, CancellationToken cancellationToken = default)
    {
        if (priceKeys.Count is < 1 or > 20) throw new InvalidOperationException("One or more trusted catalog price keys are required.");
        var results = priceKeys.Select(key =>
        {
            var price = catalog.ResolveByManifestKey(key);
            return new PricePreview(key, price.UnitAmount, price.Currency, price.Type, price.Interval,
                $"{price.Currency} {(price.UnitAmount / 100m).ToString("0.00", CultureInfo.InvariantCulture)}");
        }).ToArray();
        await store.RecordProviderEvidenceAsync("price-preview", cancellationToken);
        return results;
    }

    public async Task<CheckoutSession> CreateCheckoutAsync(string buyerKey, string priceKey, CancellationToken cancellationToken = default)
    {
        ProjectPaymentSecurity.RequireIdentifier(buyerKey, "Authenticated buyer");
        var price = catalog.ResolveByManifestKey(priceKey);
        await store.BindCustomerAsync(buyerKey, buyerKey, cancellationToken);
        return new($"sim_checkout_{ProjectPaymentSecurity.StableId(buyerKey, price.ExternalId)}", timeProvider.GetUtcNow().AddMinutes(15));
    }

    public async Task<PortalSession> CreatePortalAsync(string buyerKey, CancellationToken cancellationToken = default)
    {
        ProjectPaymentSecurity.RequireIdentifier(buyerKey, "Authenticated buyer");
        await store.BindCustomerAsync(buyerKey, buyerKey, cancellationToken);
        await store.RecordProviderEvidenceAsync("customer-portal", cancellationToken);
        return new(new Uri($"https://simulator.invalid/portal/{Uri.EscapeDataString(catalog.EnvironmentExternalId)}/{Uri.EscapeDataString(buyerKey)}"),
            timeProvider.GetUtcNow().AddMinutes(15));
    }
}

public sealed class InvalidSimulatorEventException(string message) : InvalidOperationException(message);

public static class ProjectPaymentSignature
{
    public static string Sign(ReadOnlySpan<byte> rawBody, string secret, DateTimeOffset signedAt)
    {
        if (!ProjectPaymentSecurity.HasStrongSecret(secret)) throw new InvalidOperationException("A 256-bit webhook secret is required.");
        var timestamp = signedAt.ToUnixTimeSeconds();
        var digest = Digest(rawBody, Encoding.UTF8.GetBytes(secret), timestamp);
        return $"ts={timestamp};h1={Convert.ToHexStringLower(digest)}";
    }

    public static bool Verify(ReadOnlySpan<byte> rawBody, string signature, string secret, DateTimeOffset now, TimeSpan? tolerance = null)
    {
        if (rawBody.IsEmpty || !ProjectPaymentSecurity.HasStrongSecret(secret) || string.IsNullOrWhiteSpace(signature)) return false;
        var parts = signature.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var timestamps = parts.Where(value => value.StartsWith("ts=", StringComparison.Ordinal)).ToArray();
        var digests = parts.Where(value => value.StartsWith("h1=", StringComparison.Ordinal)).ToArray();
        if (timestamps.Length != 1 || digests.Length == 0 || !long.TryParse(timestamps[0].AsSpan(3), NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp))
            return false;
        DateTimeOffset signedAt;
        try { signedAt = DateTimeOffset.FromUnixTimeSeconds(timestamp); }
        catch (ArgumentOutOfRangeException) { return false; }
        if ((now - signedAt).Duration() > (tolerance ?? TimeSpan.FromMinutes(5))) return false;
        var expected = Digest(rawBody, Encoding.UTF8.GetBytes(secret), timestamp);
        foreach (var value in digests)
        {
            byte[] supplied;
            try { supplied = Convert.FromHexString(value.AsSpan(3)); }
            catch (FormatException) { continue; }
            if (supplied.Length == expected.Length && CryptographicOperations.FixedTimeEquals(supplied, expected)) return true;
        }
        return false;
    }

    private static byte[] Digest(ReadOnlySpan<byte> rawBody, ReadOnlySpan<byte> secret, long timestamp)
    {
        var prefix = Encoding.ASCII.GetBytes(timestamp.ToString(CultureInfo.InvariantCulture) + ":");
        var signed = new byte[prefix.Length + rawBody.Length];
        prefix.CopyTo(signed, 0);
        rawBody.CopyTo(signed.AsSpan(prefix.Length));
        return HMACSHA256.HashData(secret, signed);
    }
}

public sealed record ProjectPaymentVerificationStatus(bool LifecyclePassed, bool DurableInbox, bool RestartReplayPassed);

public sealed record ProjectPaymentVerifierResult(
    string Provider,
    bool PaymentsEnabled,
    bool VerifierEnabled,
    string CommitSha,
    string ManifestDigest,
    bool LifecyclePassed,
    bool DurableInbox,
    bool RestartReplayPassed);

public static class ProjectPaymentVerifier
{
    private static readonly Regex CommitPattern = new("^[0-9a-f]{40}$", RegexOptions.CultureInvariant);
    private static readonly Regex DigestPattern = new("^[0-9a-f]{64}$", RegexOptions.CultureInvariant);

    public static async Task<ProjectPaymentVerifierResult?> BuildAsync(
        ProjectPaymentRuntimeConfiguration configuration,
        string suppliedSecret,
        string expectedCommit,
        string expectedManifestDigest,
        DurableProjectPaymentStore store,
        CancellationToken cancellationToken = default)
    {
        if (configuration.Provider != ProjectPaymentProviderMode.Simulator || !configuration.PaymentsEnabled || !configuration.VerifierEnabled)
            return null;
        if (!ProjectPaymentSecurity.HasStrongSecret(configuration.WebhookSecret)
            || !ProjectPaymentSecurity.ConstantText(suppliedSecret, configuration.WebhookSecret)
            || !CommitPattern.IsMatch(configuration.BuiltCommitSha)
            || !DigestPattern.IsMatch(configuration.ManifestDigest)
            || !ProjectPaymentSecurity.ConstantText(expectedCommit, configuration.BuiltCommitSha)
            || !ProjectPaymentSecurity.ConstantText(expectedManifestDigest, configuration.ManifestDigest))
            return null;
        string expectedScope;
        try { expectedScope = ProjectPaymentEvidenceScope.Compute(configuration.EnvironmentId, configuration.ManifestDigest, configuration.BuiltCommitSha); }
        catch (InvalidOperationException) { return null; }
        if (!ProjectPaymentSecurity.ConstantText(store.EvidenceScope, expectedScope)) return null;
        var evidence = await store.VerificationStatusAsync(expectedScope, cancellationToken);
        if (!evidence.LifecyclePassed || !evidence.DurableInbox || !evidence.RestartReplayPassed) return null;
        return new("simulator", true, true, configuration.BuiltCommitSha, configuration.ManifestDigest, true, true, true);
    }
}

public static class ProjectPaymentSecurity
{
    private static readonly Regex IdentifierPattern = new("^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$", RegexOptions.CultureInvariant);

    public static bool HasStrongSecret(string? secret) => secret is not null && Encoding.UTF8.GetByteCount(secret) >= 32;

    public static bool ConstantText(string? actual, string? expected) => CryptographicOperations.FixedTimeEquals(
        SHA256.HashData(Encoding.UTF8.GetBytes(actual ?? string.Empty)),
        SHA256.HashData(Encoding.UTF8.GetBytes(expected ?? string.Empty)));

    public static void RequireIdentifier(string? value, string label)
    {
        if (value is null || !IdentifierPattern.IsMatch(value)) throw new InvalidOperationException($"{label} is invalid.");
    }

    public static string StableId(params string[] values) => Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(string.Join(':', values))))[..24];
}
