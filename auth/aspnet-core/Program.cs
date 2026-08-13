using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
var authEnabled = string.Equals(
    builder.Configuration["VIBENEST_AUTH_ENABLED"],
    "true",
    StringComparison.OrdinalIgnoreCase);
var issuer = Require("VIBENEST_AUTH_ISSUER").TrimEnd('/') + "/";
var clientId = Require("VIBENEST_AUTH_CLIENT_ID");
var clientSecret = Require("VIBENEST_AUTH_CLIENT_SECRET");
var redirectUri = new Uri(Require("VIBENEST_AUTH_REDIRECT_URI"), UriKind.Absolute);
var appOrigin = redirectUri.GetLeftPart(UriPartial.Authority) + "/";

builder.Services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN");
builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddCookie(options =>
    {
        options.Cookie.Name = "vibenest_reference_session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    })
    .AddOpenIdConnect(options =>
    {
        options.Authority = issuer;
        options.ClientId = clientId;
        options.ClientSecret = clientSecret;
        options.CallbackPath = redirectUri.AbsolutePath;
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.ResponseMode = OpenIdConnectResponseMode.Query;
        options.UsePkce = true;
        options.RequireHttpsMetadata = true;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.SaveTokens = false;
        options.MapInboundClaims = false;
        options.Scope.Clear();
        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = clientId,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            NameClaimType = "name"
        };
        options.CorrelationCookie.HttpOnly = true;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.NonceCookie.HttpOnly = true;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Events = new OpenIdConnectEvents
        {
            // Never derive OAuth redirect targets from request Host/X-Forwarded-*.
            // Coolify terminates TLS at its proxy, so the server-side allowlisted URI is
            // both the secure source of truth and the correct public HTTPS callback.
            OnRedirectToIdentityProvider = context =>
            {
                context.ProtocolMessage.RedirectUri = redirectUri.AbsoluteUri;
                return Task.CompletedTask;
            },
            OnAuthorizationCodeReceived = context =>
            {
                (context.TokenEndpointRequest
                    ?? throw new InvalidOperationException("OIDC token request was not created."))
                    .RedirectUri = redirectUri.AbsoluteUri;
                return Task.CompletedTask;
            },
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                context.ProtocolMessage.PostLogoutRedirectUri = appOrigin;
                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapGet("/healthz", () => Results.Text("Healthy"));
app.MapGet("/auth/vibenest/login", (string? returnUrl) =>
{
    var safeReturnUrl = IsLocalReturnUrl(returnUrl) ? returnUrl! : "/";
    return Results.Challenge(
        new AuthenticationProperties { RedirectUri = safeReturnUrl },
        [OpenIdConnectDefaults.AuthenticationScheme]);
});

app.MapPost("/auth/logout", async (HttpContext context, IAntiforgery antiforgery) =>
    {
        await antiforgery.ValidateRequestAsync(context);
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            [OpenIdConnectDefaults.AuthenticationScheme]);
    })
    .RequireAuthorization();

app.MapGet("/api/session", (ClaimsPrincipal user) => Results.Json(new
{
    authenticated = user.Identity?.IsAuthenticated == true,
    subject = user.FindFirstValue("sub"),
    email = user.FindFirstValue("email"),
    emailVerified = user.FindFirstValue("email_verified")
}))
    .RequireAuthorization();

app.MapGet("/", (HttpContext context, IAntiforgery antiforgery) =>
{
    var tokens = antiforgery.GetAndStoreTokens(context);
    var authenticated = context.User.Identity?.IsAuthenticated == true;
    var subject = context.User.FindFirstValue("sub");
    var action = authenticated
        ? $"""
           <p id="subject">subject: <code>{WebUtility.HtmlEncode(subject)}</code></p>
           <form method="post" action="/auth/logout">
             <input type="hidden" name="{tokens.FormFieldName}" value="{WebUtility.HtmlEncode(tokens.RequestToken)}">
             <button type="submit">Logout locally and from VibeNest</button>
           </form>
           """
        : "<a id=\"login\" href=\"/auth/vibenest/login\">Sign in with VibeNest</a>";
    return Results.Content(
        $"<meta charset=\"utf-8\"><title>VibeNest Auth reference</title><h1>VibeNest Auth reference</h1><p>enabled: {authEnabled}</p>{action}",
        "text/html");
});

app.Run();

string Require(string key) => builder.Configuration[key]
    ?? throw new InvalidOperationException($"Missing required server environment variable {key}.");

static bool IsLocalReturnUrl(string? value) =>
    !string.IsNullOrWhiteSpace(value)
    && value[0] == '/'
    && (value.Length == 1 || (value[1] != '/' && value[1] != '\\'));

public partial class Program;
