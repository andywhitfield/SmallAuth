using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SmallAuth.Models;
using SmallAuth.ViewModels.Manage;

namespace SmallAuth.Controllers
{
    [Authorize]
    public class ManageController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger _logger;

        public ManageController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ILoggerFactory loggerFactory)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = loggerFactory.CreateLogger<ManageController>();
        }

        [HttpGet]
        public async Task<IActionResult> Index(bool? success = null)
        {
            var user = await GetCurrentUserAsync();
            var model = new IndexViewModel
            {
                StatusMessage =
                    success == null ? string.Empty
                    : success.GetValueOrDefault(false) ? "Your details have been updated successfully."
                    : "Sorry, an error occurred trying to update your details. Please try again later.",
                Email = user.Email,
                DisplayName = user.DisplayName
            };
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(IndexViewModel model)
        {
            if (!ModelState.IsValid)
                return View(nameof(Index), model);

            var user = await GetCurrentUserAsync();
            if (user != null)
            {
                if (model.DisplayName != user.DisplayName)
                {
                    user.DisplayName = model.DisplayName;
                    var result = await _userManager.UpdateAsync(user);
                    if (!result.Succeeded)
                    {
                        foreach (var error in result.Errors)
                            ModelState.AddModelError(string.Empty, error.Description);

                        return View(nameof(Index), model);
                    }
                
                    _logger.LogInformation(4, "User changed their display name successfully.");
                }

                if (!string.IsNullOrEmpty(model.Password) &&
                    !string.IsNullOrEmpty(model.NewPassword))
                {
                    var result = await _userManager.ChangePasswordAsync(user, model.Password, model.NewPassword);
                    if (!result.Succeeded)
                    {
                        foreach (var error in result.Errors)
                            ModelState.AddModelError(string.Empty, error.Description);

                        return View(nameof(Index), model);
                    }

                    await _signInManager.SignInAsync(user, isPersistent: false);
                    _logger.LogInformation(3, "User changed their password successfully.");
                }

                return RedirectToAction(nameof(Index), new { success = true });                
            }
            
            return RedirectToAction(nameof(Index), new { success = false });
        }

        private Task<ApplicationUser> GetCurrentUserAsync()
        {
            return _userManager.GetUserAsync(User);
        }
    }
}