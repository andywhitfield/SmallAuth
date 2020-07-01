using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OpenIddict.EntityFrameworkCore.Models;
using SmallAuth.ViewModels.AppManager;

namespace SmallAuth.Controllers
{
    [Authorize(Policy = "SuperUser")]
    public class AppManagerController : Controller
    {
        private readonly ILogger _logger;
        private readonly OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication> _openIddictApplicationManager;

        public AppManagerController(
            OpenIddictApplicationManager<OpenIddictEntityFrameworkCoreApplication> openIddictApplicationManager,
            ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<ManageController>();
            _openIddictApplicationManager = openIddictApplicationManager;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View(new IndexViewModel
            {
                AllApplications = await LoadAllAppsAsync()
            });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Add(IndexViewModel model)
        {
            if (!ModelState.IsValid)
            {
                model.AllApplications = await LoadAllAppsAsync();
                return View(nameof(Index), model);
            }

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = model.ClientId,
                ClientSecret = model.ClientSecret,
                DisplayName = model.DisplayName,
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Logout,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                }
            };
            AddUris(model.RedirectUris, u => descriptor.RedirectUris.Add(u));
            AddUris(model.PostLogoutRedirectUris, u => descriptor.PostLogoutRedirectUris.Add(u));

            await _openIddictApplicationManager.CreateAsync(descriptor);

            return RedirectToAction(nameof(Index));
        }

        [HttpGet]
        public async Task<IActionResult> Delete(string app)
        {
            var descriptor = await _openIddictApplicationManager.FindByClientIdAsync(app);
            if (descriptor != null)
                await _openIddictApplicationManager.DeleteAsync(descriptor);

            return RedirectToAction(nameof(Index));
        }

        private async Task<List<(string ClientId, string DisplayName, string PostLogoutRedirectUris, string RedirectUris)>> LoadAllAppsAsync()
        {
            var allApps = new List<(string ClientId, string DisplayName, string PostLogoutRedirectUris, string RedirectUris)>();
            await foreach (var app in _openIddictApplicationManager.ListAsync())
                allApps.Add((app.ClientId, app.DisplayName, app.PostLogoutRedirectUris, app.RedirectUris));
            return allApps;
        }

        private void AddUris(string uris, Action<Uri> callback)
        {
            foreach (var uri in uris.Split(new char[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (string.IsNullOrWhiteSpace(uri))
                    continue;
                if (!Uri.TryCreate(uri, UriKind.Absolute, out var u))
                    throw new ApplicationException($"{uri} is not a valid URI.");
                callback(u);
            }
        }
    }
}