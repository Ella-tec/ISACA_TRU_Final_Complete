using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace IsaChatApp.Services;

/// <summary>
/// Sign-in against the team's Keycloak server.
///
/// How it fits together:
///   1. The sign-in page (Components/Pages/SignIn.razor) sends the email
///      address and password here. They go straight to Keycloak's token
///      endpoint; this app never stores the password.
///   2. If Keycloak accepts them, it sends back a signed access token
///      (plus a refresh token). Those tokens stay on the server, in memory,
///      under a random session ID.
///   3. The browser only gets an encrypted sign-in cookie holding the
///      person's ID, name, email, roles and that session ID.
///   4. When the chat sends a question, ChatWidget asks this service for
///      a current access token for the session and passes it to the
///      pipeline, where the access_control stage checks it.
///
/// Sign-in is by EMAIL ADDRESS, never by name, so it works the same for
/// every chapter in every country. Passwords can contain any characters.
/// Username may also be the short Keycloak id (e.g. staff.dev); email form
/// staff.dev@example.org is normalized to staff.dev.
///
/// Keycloak settings live in appsettings.json under "Keycloak" -- see
/// docs/sign-in-setup.md for what the Keycloak client needs.
///
/// Prototype limits: tokens are kept in memory, so restarting the app signs
/// everyone out. Refresh is best-effort. Logout calls Keycloak when possible.
/// </summary>
public sealed class KeycloakSignInService
{
    /// <summary>Claim type for the in-memory token session id on the cookie principal.</summary>
    public const string SessionClaim = "isa_session";

    /// <summary>Optional display greeting claim.</summary>
    public const string GreetingClaim = "isa_greeting";

    /// <summary>Locale claim when present on the token.</summary>
    public const string LocaleClaim = "locale";

    /// <summary>Directory / person id claim used by notebook and journey panels.</summary>
    public const string PersonIdClaim = "person_id";

    private readonly IHttpClientFactory _httpFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<KeycloakSignInService> _log;
    private readonly ConcurrentDictionary<string, StoredTokens> _sessions = new();

    public KeycloakSignInService(IHttpClientFactory httpFactory, IConfiguration config, ILogger<KeycloakSignInService> log)
    {
        _httpFactory = httpFactory;
        _config = config;
        _log = log;
    }

    private HttpClient _http => _httpFactory.CreateClient();

    private string Authority => (_config["Keycloak:Authority"] ?? "").TrimEnd('/');
    private string ClientId => _config["Keycloak:ClientId"] ?? "";
    private string? ClientSecret =>
        string.IsNullOrWhiteSpace(_config["Keycloak:ClientSecret"]) ? null : _config["Keycloak:ClientSecret"];

    private string TokenEndpoint => $"{Authority}/protocol/openid-connect/token";
    private string LogoutEndpoint => $"{Authority}/protocol/openid-connect/logout";

    public async Task<SignInResult> SignInAsync(string email, string password, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(Authority) || string.IsNullOrEmpty(ClientId))
        {
            _log.LogWarning("Sign-in attempted but Keycloak:Authority or Keycloak:ClientId is not set in appsettings.json.");
            return new SignInResult(SignInOutcome.NotConfigured);
        }

        // Accept staff.dev or staff.dev@example.org (Keycloak usernames are local-part).
        var username = NormalizeUsername(email);

        var form = BaseForm();
        form["grant_type"] = "password";
        form["username"] = username;
        form["password"] = password;
        form["scope"] = "openid profile email";

        TokenResponse? tokens;
        try
        {
            using var response = await _http.PostAsync(TokenEndpoint, new FormUrlEncodedContent(form), ct);

            if (response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized)
            {
                var error = await ReadErrorAsync(response, ct);

                if (error.Error == "invalid_grant")
                {
                    _log.LogInformation("Sign-in refused by Keycloak: {Description}", error.Description);
                    return new SignInResult(SignInOutcome.WrongCredentials);
                }

                _log.LogWarning("Keycloak rejected the sign-in request: {Error} - {Description}. Check the client settings in docs/sign-in-setup.md.",
                    error.Error, error.Description);
                return new SignInResult(SignInOutcome.NotConfigured);
            }

            if (!response.IsSuccessStatusCode)
            {
                _log.LogWarning("Keycloak token endpoint returned {Status}", (int)response.StatusCode);
                return new SignInResult(SignInOutcome.ServiceError);
            }

            tokens = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Keycloak token request failed. Is Keycloak running at {Authority}?", Authority);
            return new SignInResult(SignInOutcome.ServiceError);
        }

        if (tokens is null || string.IsNullOrEmpty(tokens.AccessToken))
            return new SignInResult(SignInOutcome.ServiceError);

        var sessionId = Guid.NewGuid().ToString("N");
        _sessions[sessionId] = StoredTokens.From(tokens);
        return new SignInResult(SignInOutcome.Success, BuildPrincipal(tokens.AccessToken, sessionId));
    }

    private static string NormalizeUsername(string emailOrUser)
    {
        var s = (emailOrUser ?? string.Empty).Trim();
        if (s.Length == 0) return s;
        var at = s.IndexOf('@');
        if (at > 0) s = s[..at];
        return s;
    }

    public async Task<string?> GetAccessTokenAsync(string? sessionId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(sessionId) || !_sessions.TryGetValue(sessionId, out var stored))
            return null;

        if (stored.AccessExpiresUtc > DateTime.UtcNow.AddSeconds(30))
            return stored.AccessToken;

        if (string.IsNullOrEmpty(stored.RefreshToken))
        {
            _sessions.TryRemove(sessionId, out _);
            return null;
        }

        var form = BaseForm();
        form["grant_type"] = "refresh_token";
        form["refresh_token"] = stored.RefreshToken;

        try
        {
            using var response = await _http.PostAsync(TokenEndpoint, new FormUrlEncodedContent(form), ct);
            if (!response.IsSuccessStatusCode)
            {
                _sessions.TryRemove(sessionId, out _);
                return null;
            }

            var tokens = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: ct);
            if (tokens is null || string.IsNullOrEmpty(tokens.AccessToken))
            {
                _sessions.TryRemove(sessionId, out _);
                return null;
            }

            _sessions[sessionId] = StoredTokens.From(tokens);
            return tokens.AccessToken;
        }
        catch
        {
            _sessions.TryRemove(sessionId, out _);
            return null;
        }
    }

    public async Task SignOutKeycloakAsync(string? sessionId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(sessionId) || !_sessions.TryRemove(sessionId, out var stored))
            return;

        if (string.IsNullOrEmpty(stored.RefreshToken))
            return;

        try
        {
            var form = BaseForm();
            form["refresh_token"] = stored.RefreshToken;
            await _http.PostAsync(LogoutEndpoint, new FormUrlEncodedContent(form), ct);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Keycloak logout call failed (session already cleared locally).");
        }
    }

    private Dictionary<string, string> BaseForm()
    {
        var form = new Dictionary<string, string>
        {
            ["client_id"] = ClientId
        };
        if (!string.IsNullOrEmpty(ClientSecret))
            form["client_secret"] = ClientSecret;
        return form;
    }

    private static ClaimsPrincipal BuildPrincipal(string accessToken, string sessionId)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(accessToken);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, jwt.Subject ?? sessionId),
            new(SessionClaim, sessionId),
        };

        string? name = jwt.Claims.FirstOrDefault(c => c.Type == "name")?.Value
            ?? jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
        if (!string.IsNullOrEmpty(name))
            claims.Add(new Claim(ClaimTypes.Name, name));

        var email = jwt.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
        if (!string.IsNullOrEmpty(email))
            claims.Add(new Claim(ClaimTypes.Email, email));

        // person_id may live as a custom claim or preferred_username for directory linkage
        var personId = jwt.Claims.FirstOrDefault(c => c.Type == PersonIdClaim)?.Value
            ?? jwt.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
        if (personId is not null)
            claims.Add(new Claim(PersonIdClaim, personId));

        foreach (var role in ExtractRoles(jwt))
            claims.Add(new Claim(ClaimTypes.Role, role));

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        return new ClaimsPrincipal(identity);
    }

    private static IEnumerable<string> ExtractRoles(JwtSecurityToken jwt)
    {
        var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in jwt.Claims.Where(c => c.Type is "role" or ClaimTypes.Role))
            roles.Add(c.Value);

        if (jwt.Payload.TryGetValue("realm_access", out var realmObj) && realmObj is JsonElement el &&
            el.TryGetProperty("roles", out var rolesEl) && rolesEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var r in rolesEl.EnumerateArray())
            {
                var v = r.GetString();
                if (!string.IsNullOrEmpty(v)) roles.Add(v);
            }
        }

        if (jwt.Payload.TryGetValue("resource_access", out var resObj) && resObj is JsonElement resEl)
        {
            foreach (var client in resEl.EnumerateObject())
            {
                if (client.Value.TryGetProperty("roles", out var clientRoles) && clientRoles.ValueKind == JsonValueKind.Array)
                {
                    foreach (var r in clientRoles.EnumerateArray())
                    {
                        var v = r.GetString();
                        if (!string.IsNullOrEmpty(v)) roles.Add(v);
                    }
                }
            }
        }

        return roles;
    }

    private static async Task<(string Error, string Description)> ReadErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        try
        {
            var body = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
            var err = body.TryGetProperty("error", out var e) ? e.GetString() ?? "" : "";
            var desc = body.TryGetProperty("error_description", out var d) ? d.GetString() ?? "" : "";
            return (err, desc);
        }
        catch
        {
            return ("", "");
        }
    }

    private sealed class TokenResponse
    {
        [JsonPropertyName("access_token")] public string AccessToken { get; set; } = "";
        [JsonPropertyName("refresh_token")] public string? RefreshToken { get; set; }
        [JsonPropertyName("expires_in")] public int ExpiresIn { get; set; }
        [JsonPropertyName("refresh_expires_in")] public int RefreshExpiresIn { get; set; }
    }

    private sealed class StoredTokens
    {
        public string AccessToken { get; init; } = "";
        public string? RefreshToken { get; init; }
        public DateTime AccessExpiresUtc { get; init; }

        public static StoredTokens From(TokenResponse t) => new()
        {
            AccessToken = t.AccessToken,
            RefreshToken = t.RefreshToken,
            AccessExpiresUtc = DateTime.UtcNow.AddSeconds(Math.Max(30, t.ExpiresIn - 15))
        };
    }
}

public enum SignInOutcome { Success, WrongCredentials, NotConfigured, ServiceError }

public sealed class SignInResult
{
    public SignInOutcome Outcome { get; }
    public ClaimsPrincipal? Principal { get; }
    public SignInResult(SignInOutcome outcome, ClaimsPrincipal? principal = null)
    {
        Outcome = outcome;
        Principal = principal;
    }
}
