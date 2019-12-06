using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using SmallAuth.Models;

namespace SmallAuth.Controllers
{
    public class UserinfoController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public UserinfoController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
        [HttpGet("~/connect/userinfo"), Produces("application/json")]
        public async Task<IActionResult> Userinfo()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Challenge(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var claims = new Dictionary<string, object>(StringComparer.Ordinal);

            // Note: the "sub" claim is a mandatory claim and must be included in the JSON response.
            claims[OpenIddictConstants.Claims.Subject] = await _userManager.GetUserIdAsync(user);

            if (User.HasClaim(OpenIddictConstants.Claims.Scope, OpenIddictConstants.Scopes.Email))
            {
                claims[OpenIddictConstants.Claims.Email] = await _userManager.GetEmailAsync(user);
                claims[OpenIddictConstants.Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
            }

            if (User.HasClaim(OpenIddictConstants.Claims.Scope, "roles"))
                claims["roles"] = await _userManager.GetRolesAsync(user);

            return Ok(claims);
        }
    }
}
