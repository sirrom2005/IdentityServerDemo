using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Client
{
    [Authorize]
    public class ProfileController : Controller
    {
        public async Task<IActionResult> Index()
        {
            // Get the access token
            var accessToken = await HttpContext.GetTokenAsync("access_token");

            // Get the ID token
            var idToken = await HttpContext.GetTokenAsync("id_token");

            // Get user claims
            var claims = User.Claims.Select(c => new { c.Type, c.Value });

            return View(claims);
        }
    }
}
