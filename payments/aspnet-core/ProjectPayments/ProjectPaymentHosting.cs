using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Fixture.ProjectPayments;

public sealed class FixtureBuyerAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string AuthenticationScheme = "FixtureOpaqueBuyer";
    public const string Header = "X-Fixture-Authenticated-Buyer";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var raw = Request.Headers[Header].ToString();
        try { ProjectPaymentSecurity.RequireIdentifier(raw, "Authenticated buyer"); }
        catch (InvalidOperationException) { return Task.FromResult(AuthenticateResult.NoResult()); }
        var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, raw)], AuthenticationScheme);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), AuthenticationScheme)));
    }
}

public sealed class ProjectPaymentInboxWorker(
    DurableProjectPaymentStore store,
    ILogger<ProjectPaymentInboxWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await store.ProcessDueAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) { logger.LogError(exception, "Project Payment inbox processing failed; durable rows remain due."); }
            try { await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}

public static class ProjectPaymentIdentity
{
    public static string RequiredSubject(ClaimsPrincipal user)
    {
        var subject = user.FindFirstValue(ClaimTypes.NameIdentifier);
        ProjectPaymentSecurity.RequireIdentifier(subject, "Authenticated buyer");
        return subject!;
    }
}
