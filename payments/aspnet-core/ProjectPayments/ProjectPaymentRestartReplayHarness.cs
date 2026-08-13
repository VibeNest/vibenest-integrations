using System.Buffers;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Fixture.ProjectPayments;

public enum ProjectPaymentHarnessBodyStatus
{
    Valid,
    Invalid,
    TooLarge
}

public static class ProjectPaymentRestartReplayHarness
{
    public const int MaxBodyBytes = 1024;
    public const string Action = "restart-replay";

    public static bool IsAuthorized(ProjectPaymentRuntimeConfiguration configuration, string? suppliedSecret) =>
        configuration.Provider == ProjectPaymentProviderMode.Simulator
        && configuration.PaymentsEnabled
        && configuration.VerifierEnabled
        && ProjectPaymentSecurity.HasStrongSecret(configuration.WebhookSecret)
        && ProjectPaymentSecurity.HasStrongSecret(suppliedSecret)
        && ProjectPaymentSecurity.ConstantText(suppliedSecret, configuration.WebhookSecret);

    public static bool MatchesExpectedBuild(
        ProjectPaymentRuntimeConfiguration configuration,
        string? expectedCommit,
        string? expectedManifestDigest) =>
        IsLowerHex(expectedCommit, 40)
        && IsLowerHex(expectedManifestDigest, 64)
        && ProjectPaymentSecurity.ConstantText(expectedCommit, configuration.BuiltCommitSha)
        && ProjectPaymentSecurity.ConstantText(expectedManifestDigest, configuration.ManifestDigest);

    public static async ValueTask<ProjectPaymentHarnessBodyStatus> ReadBodyAsync(
        HttpRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.ContentLength is > MaxBodyBytes)
            return ProjectPaymentHarnessBodyStatus.TooLarge;

        var rented = ArrayPool<byte>.Shared.Rent(MaxBodyBytes + 1);
        try
        {
            var total = 0;
            while (total <= MaxBodyBytes)
            {
                var read = await request.Body.ReadAsync(
                    rented.AsMemory(total, MaxBodyBytes + 1 - total),
                    cancellationToken);
                if (read == 0)
                    return IsExactStageAction(rented.AsSpan(0, total))
                        ? ProjectPaymentHarnessBodyStatus.Valid
                        : ProjectPaymentHarnessBodyStatus.Invalid;
                total += read;
            }
            return ProjectPaymentHarnessBodyStatus.TooLarge;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }

    private static bool IsExactStageAction(ReadOnlySpan<byte> body)
    {
        try
        {
            using var document = JsonDocument.Parse(body.ToArray());
            if (document.RootElement.ValueKind != JsonValueKind.Object) return false;
            var properties = document.RootElement.EnumerateObject().ToArray();
            return properties.Length == 1
                && properties[0].NameEquals("action")
                && properties[0].Value.ValueKind == JsonValueKind.String
                && properties[0].Value.GetString() == Action;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool IsLowerHex(string? value, int length) =>
        value is not null
        && value.Length == length
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
}
