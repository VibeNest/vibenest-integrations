using System.Net;
using System.Security.Claims;
using Fixture.ProjectPayments;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

public sealed class AuthFlowTests : IClassFixture<AuthFactory>
{
    private readonly HttpClient client;

    public AuthFlowTests(AuthFactory factory) => client = factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = new Uri("https://reference.example")
    });

    [Fact]
    public async Task LoginUsesCodeS256StateNonceAndPinnedCallback()
    {
        var response = await client.GetAsync("/auth/vibenest/login");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal("https://reference.example/auth/vibenest/callback", query["redirect_uri"]);
        Assert.False(string.IsNullOrWhiteSpace(query["state"]));
        Assert.False(string.IsNullOrWhiteSpace(query["nonce"]));
    }

    [Fact]
    public async Task WrongCallbackSessionAndLogoutAreRejected()
    {
        Assert.False((await client.GetAsync("/auth/vibenest/callback?code=fake&state=wrong")).IsSuccessStatusCode);
        Assert.False((await client.GetAsync("/api/session")).IsSuccessStatusCode);
        Assert.False((await client.PostAsync("/auth/logout", null)).IsSuccessStatusCode);
    }

    [Fact]
    public void PaymentsUsesTheValidatedPairwiseSubject()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "pairwise-sub")], "oidc"));
        Assert.Equal("pairwise-sub", ProjectPaymentIdentity.RequiredSubject(user));
    }
}

public sealed class AuthFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("VIBENEST_AUTH_ENABLED", "true");
        builder.UseSetting("VIBENEST_AUTH_ISSUER", "https://vibenest.net/");
        builder.UseSetting("VIBENEST_AUTH_CLIENT_ID", "reference-client");
        builder.UseSetting("VIBENEST_AUTH_CLIENT_SECRET", "placeholder-secret");
        builder.UseSetting("VIBENEST_AUTH_REDIRECT_URI", "https://reference.example/auth/vibenest/callback");
        builder.UseSetting("VIBENEST_PROJECT_PAYMENTS_ENABLED", "false");
        builder.ConfigureServices(services => services.PostConfigure<OpenIdConnectOptions>(
            OpenIdConnectDefaults.AuthenticationScheme,
            options => options.Configuration = new OpenIdConnectConfiguration
            {
                Issuer = "https://vibenest.net/",
                AuthorizationEndpoint = "https://vibenest.net/connect/authorize",
                TokenEndpoint = "https://vibenest.net/connect/token",
                UserInfoEndpoint = "https://vibenest.net/connect/userinfo",
                EndSessionEndpoint = "https://vibenest.net/connect/logout"
            }));
    }
}
