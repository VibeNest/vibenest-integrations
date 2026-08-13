using System.Net;
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
    public async Task Login_UsesCodeS256StateNonceAndPinnedCallback()
    {
        var response = await client.GetAsync("/auth/vibenest/login");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!;
        Assert.Equal("vibenest.net", location.Host);
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal("code", query["response_type"]);
        Assert.Equal("S256", query["code_challenge_method"]);
        Assert.Equal("https://reference.example/auth/vibenest/callback", query["redirect_uri"]);
        Assert.False(string.IsNullOrWhiteSpace(query["state"]));
        Assert.False(string.IsNullOrWhiteSpace(query["nonce"]));
    }

    [Fact]
    public async Task CallbackWithWrongStateIsRejected()
    {
        var response = await client.GetAsync("/auth/vibenest/callback?code=fake&state=wrong");
        Assert.False(response.IsSuccessStatusCode);
    }

    [Fact]
    public async Task SessionAndLogoutRequireAuthenticatedLocalSession()
    {
        Assert.False((await client.GetAsync("/api/session")).IsSuccessStatusCode);
        Assert.False((await client.PostAsync("/auth/logout", null)).IsSuccessStatusCode);
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
