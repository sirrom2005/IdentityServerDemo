using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Client.Pages.Account
{
    public class LoginModel : PageModel
    {
        public IActionResult OnGet(string returnUrl = "/")
        {
            return Challenge(
                new AuthenticationProperties { 
                    RedirectUri = returnUrl,
                    IsPersistent = true
                },
                OpenIdConnectDefaults.AuthenticationScheme
               );
        }
    }
}
