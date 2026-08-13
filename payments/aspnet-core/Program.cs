using System.Text.Json;
using Fixture.ProjectPayments;
using Microsoft.AspNetCore.Authentication;

const string verifierPath = "/.well-known/vibenest/project-payments/verifier";
const string harnessPath = "/.well-known/vibenest/project-payments/harness";

var builder = WebApplication.CreateBuilder(args);
var runtime = ProjectPaymentRuntimeConfiguration.From(builder.Configuration);
builder.Services.AddSingleton(runtime);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddAuthentication(FixtureBuyerAuthenticationHandler.AuthenticationScheme)
    .AddScheme<AuthenticationSchemeOptions, FixtureBuyerAuthenticationHandler>(FixtureBuyerAuthenticationHandler.AuthenticationScheme, _ => { });
builder.Services.AddAuthorization();

if (runtime.PaymentsEnabled && runtime.Provider == ProjectPaymentProviderMode.Simulator)
{
    var catalog = runtime.LoadCatalog();
    builder.Services.AddSingleton(catalog);
    builder.Services.AddSingleton(provider => new DurableProjectPaymentStore(
        builder.Configuration["PROJECT_PAYMENT_FIXTURE_STORE"] ?? Path.Combine(AppContext.BaseDirectory, ".data", "project-payments.sqlite"),
        catalog,
        runtime.EvidenceScope,
        provider.GetRequiredService<TimeProvider>()));
    builder.Services.AddSingleton<IProjectPaymentProvider, SimulatorProjectPaymentProvider>();
    builder.Services.AddHostedService<ProjectPaymentInboxWorker>();
}
else
{
    builder.Services.AddSingleton<IProjectPaymentProvider, DisabledProjectPaymentProvider>();
}

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

if (runtime.PaymentsEnabled && runtime.Provider == ProjectPaymentProviderMode.Simulator)
{
    app.MapPost("/webhooks/project-payments", async (
        HttpRequest request,
        DurableProjectPaymentStore store,
        ProjectPaymentCatalog catalog,
        ProjectPaymentRuntimeConfiguration configuration,
        CancellationToken cancellationToken) =>
    {
        var rawBody = await ProjectPaymentWebhookBodyReader.TryReadAsync(request, cancellationToken);
        if (rawBody is null) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        if (!ProjectPaymentSignature.Verify(
                rawBody,
                request.Headers["Paddle-Signature"].ToString(),
                configuration.WebhookSecret,
                DateTimeOffset.UtcNow))
            return Results.Unauthorized();
        try
        {
            var normalized = await ProjectPaymentProtocol.NormalizeVerifiedEventAsync(
                rawBody,
                catalog.EnvironmentExternalId,
                catalog,
                store,
                cancellationToken);
            await store.InsertVerifiedEventAsync(normalized, cancellationToken);
            return Results.Accepted();
        }
        catch (InvalidSimulatorEventException exception)
        {
            return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Invalid simulator event", detail: exception.Message);
        }
    });

    app.MapGet("/api/project-payments/prices", async (
        string[] priceKey,
        HttpContext context,
        IProjectPaymentProvider provider,
        CancellationToken cancellationToken) =>
    {
        _ = ProjectPaymentIdentity.RequiredSubject(context.User);
        return Results.Ok(await provider.PreviewPricesAsync(priceKey, cancellationToken));
    }).RequireAuthorization();

    app.MapPost("/api/project-payments/checkout", async (
        JsonElement body,
        HttpContext context,
        IProjectPaymentProvider provider,
        CancellationToken cancellationToken) =>
    {
        var priceKey = StrictCheckoutPriceKey(body);
        var buyer = ProjectPaymentIdentity.RequiredSubject(context.User);
        return Results.Ok(await provider.CreateCheckoutAsync(buyer, priceKey, cancellationToken));
    }).RequireAuthorization();

    app.MapPost("/api/project-payments/portal", async (
        HttpContext context,
        IProjectPaymentProvider provider,
        CancellationToken cancellationToken) =>
    {
        var buyer = ProjectPaymentIdentity.RequiredSubject(context.User);
        return Results.Ok(await provider.CreatePortalAsync(buyer, cancellationToken));
    }).RequireAuthorization();

    app.MapGet("/api/project-payments/entitlements/{grantKey}", async (
        string grantKey,
        HttpContext context,
        DurableProjectPaymentStore store,
        CancellationToken cancellationToken) =>
    {
        var buyer = ProjectPaymentIdentity.RequiredSubject(context.User);
        return Results.Ok(new { grantKey, active = await store.HasEntitlementAsync(buyer, grantKey, cancellationToken) });
    }).RequireAuthorization();

    app.MapPost(harnessPath, async (
        HttpRequest request,
        DurableProjectPaymentStore store,
        ProjectPaymentRuntimeConfiguration configuration,
        CancellationToken cancellationToken) =>
    {
        if (!ProjectPaymentRestartReplayHarness.IsAuthorized(
                configuration,
                request.Headers["X-VibeNest-Simulator-Secret"].ToString()))
            return Results.NotFound();
        if (!ProjectPaymentRestartReplayHarness.MatchesExpectedBuild(
                configuration,
                request.Headers["X-VibeNest-Expected-Commit"].ToString(),
                request.Headers["X-VibeNest-Expected-Manifest-Digest"].ToString()))
            return Results.NotFound();
        if (!request.HasJsonContentType()) return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
        var bodyStatus = await ProjectPaymentRestartReplayHarness.ReadBodyAsync(request, cancellationToken);
        if (bodyStatus == ProjectPaymentHarnessBodyStatus.TooLarge)
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        if (bodyStatus != ProjectPaymentHarnessBodyStatus.Valid) return Results.BadRequest();
        await store.StageRestartReplayProbeAsync(configuration.EnvironmentId, cancellationToken);
        return Results.Json(new { action = ProjectPaymentRestartReplayHarness.Action, state = "staged" }, statusCode: StatusCodes.Status202Accepted);
    });

    if (runtime.VerifierEnabled)
    {
        app.MapMethods(verifierPath, [HttpMethods.Get], async (
            HttpRequest request,
            DurableProjectPaymentStore store,
            ProjectPaymentRuntimeConfiguration configuration,
            CancellationToken cancellationToken) =>
        {
            var result = await ProjectPaymentVerifier.BuildAsync(
                configuration,
                request.Headers["X-VibeNest-Simulator-Secret"].ToString(),
                request.Headers["X-VibeNest-Expected-Commit"].ToString(),
                request.Headers["X-VibeNest-Expected-Manifest-Digest"].ToString(),
                store,
                cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        });
    }
}

app.Run();

static string StrictCheckoutPriceKey(JsonElement body)
{
    if (body.ValueKind != JsonValueKind.Object) throw new BadHttpRequestException("Checkout body must be an object.");
    var properties = body.EnumerateObject().ToArray();
    if (properties.Length != 1 || properties[0].Name != "priceKey" || properties[0].Value.ValueKind != JsonValueKind.String)
        throw new BadHttpRequestException("Checkout accepts only a trusted catalog priceKey.");
    var value = properties[0].Value.GetString();
    ProjectPaymentSecurity.RequireIdentifier(value, "Price key");
    return value!;
}

public partial class Program;
