using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Duende.IdentityModel.Client;
using System.Threading.Tasks;

namespace Client.Pages
{
    public class MyloginModel : PageModel
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public MyloginModel(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            public string? Username { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string? Password { get; set; }
        }

        public IActionResult OnGet()
        {
            if (User.Identity.IsAuthenticated)
            {
                return Redirect("/");
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var client = _httpClientFactory.CreateClient();

            var disco = await client.GetDiscoveryDocumentAsync("https://localhost:7295");
            if (disco.IsError)
            {
                ErrorMessage = $"Error discovering IdentityServer endpoints: {disco.Error}";
                return Page();
            }

            // Using the configuration values from your OpenID Connect setup
            var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = "interactive.client",
                ClientSecret = "secret",
                Scope = "api1 openid profile email",
                UserName = Input.Username,
                Password = Input.Password
            });

            if (tokenResponse.IsError)
            {
                ErrorMessage = $"Login failed: {tokenResponse.ErrorDescription ?? tokenResponse.Error}";
                return Page();
            }

            var claims = new List<Claim>();

            if (!string.IsNullOrEmpty(tokenResponse.IdentityToken))
            {
                // Parse the identity token to get claims
                var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                var identityToken = handler.ReadJwtToken(tokenResponse.IdentityToken);
                claims.AddRange(identityToken.Claims);
            }
            else
            {
                // Fallback claims if no identity token
                claims.Add(new Claim("sub", Input.Username));
                claims.Add(new Claim("name", Input.Username));
            }

            var claimsIdentity = new ClaimsIdentity(claims, "Cookies");
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(12)
            };

            authProperties.StoreTokens(new[]
            {
                new AuthenticationToken { Name = "access_token", Value = tokenResponse.AccessToken ?? "" },
                new AuthenticationToken { Name = "expires_at", Value = DateTimeOffset.UtcNow.AddSeconds(tokenResponse.ExpiresIn).ToString("o") },
                new AuthenticationToken { Name = "id_token", Value = tokenResponse.IdentityToken ?? "" },
                new AuthenticationToken { Name = "refresh_token", Value = tokenResponse.RefreshToken ?? "" }
            });

            await HttpContext.SignInAsync("Cookies", claimsPrincipal, authProperties);

            return Redirect("/");
        }
    }
}
