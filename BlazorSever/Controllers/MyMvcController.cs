using Duende.IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace BlazorSever.Controllers
{

    public class MyMvcController : Controller
    {
        // This action will be accessible at /MyMvc/Index
        //public IActionResult Index()
        //{
        //    // You can pass data to the view using ViewBag or a strongly-typed model
        //    ViewBag.Message = "Hello from MVC Controller!";
        //    return View(); // This will look for Views/MyMvc/Index.cshtml
        //}

        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;

        public MyMvcController(IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
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

        public IActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                return Redirect("/");
            }
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var client = _httpClientFactory.CreateClient();

            var disco = await client.GetDiscoveryDocumentAsync("https://localhost:7295");
            if (disco.IsError)
            {
                ErrorMessage = $"Error discovering IdentityServer endpoints: {disco.Error}";
                return View();
            }

            // Using the configuration values from your OpenID Connect setup
            var tokenResponse = await client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                Address = disco.TokenEndpoint,
                ClientId = "interactive.client",
                ClientSecret = _configuration["IdentityServer:Secret"],
                Scope = "api1 openid profile email",
                UserName = username,
                Password = password
            });

            if (tokenResponse.IsError)
            {
                ErrorMessage = $"Login failed: {tokenResponse.ErrorDescription ?? tokenResponse.Error}";
                return View();
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


        public async Task<IActionResult> Logout()
        {
            // 1. Sign out from your application's cookie scheme
            // This clears the local session in your Blazor app.
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // 2. Sign out from the IdentityServer (optional, but recommended for SSO)
            // You'll need the discovery document again to find the endsession_endpoint.
            var client = _httpClientFactory.CreateClient();
            var disco = await client.GetDiscoveryDocumentAsync("https://localhost:7295"); // Your IdentityServer URL

            if (disco.IsError)
            {
                // Log the error but continue to redirect locally, as the cookie is already cleared.
                Console.WriteLine($"Error discovering IdentityServer endpoints for logout: {disco.Error}");
                return RedirectToAction("Index", "Home"); // Redirect locally if IdP logout fails
            }

            // Build the logout URL for the IdentityServer
            // post_logout_redirect_uri is where IdentityServer will redirect the user AFTER it logs them out.
            // This should be one of the PostLogoutRedirectUris configured for your client in IdentityServer.
            // A common practice is to redirect back to your app's home page or a public logout confirmation page.
            var postLogoutRedirectUri = Url.Action("SignedOut", "Account", null, Request.Scheme); // Example: /Account/SignedOut or /

            // Construct the IdentityServer logout URL
            // If you need to pass an ID Token hint (recommended for OpenID Connect RP-Initiated Logout),
            // you would retrieve the ID Token saved during login from HttpContext.GetTokenAsync("id_token").
            var idToken = await HttpContext.GetTokenAsync("id_token");

            var logoutUrl = disco.EndSessionEndpoint;
            if (!string.IsNullOrEmpty(postLogoutRedirectUri))
            {
                logoutUrl += $"?post_logout_redirect_uri={Uri.EscapeDataString(postLogoutRedirectUri)}";
            }
            if (!string.IsNullOrEmpty(idToken))
            {
                // Include id_token_hint for OpenID Connect RP-Initiated Logout
                logoutUrl += (string.IsNullOrEmpty(postLogoutRedirectUri) ? "?" : "&") + $"id_token_hint={idToken}";
            }


            // Redirect the user to the IdentityServer's logout endpoint
            // The IdentityServer will handle clearing its session and then redirect the user back
            // to the post_logout_redirect_uri specified above.
            return Redirect(logoutUrl);

            // If you only want to sign out locally (not from IdP):
            // return RedirectToAction("Index", "Home"); // Or any other suitable landing page
        }

        // Optional: A page to land on after the IdP redirects back from logout
        [HttpGet]
        public IActionResult SignedOut()
        {
            ViewBag.Message = "You have successfully logged out.";
            return View(); // This would look for Views/Account/SignedOut.cshtml
        }



        [Authorize]
        public IActionResult About()
        {
            ViewData["Title"] = "About My MVC Page";
            return View(); // This will look for Views/MyMvc/About.cshtml
        }
    }
}
