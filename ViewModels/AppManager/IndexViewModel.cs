using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using SmallAuth.Attributes;

namespace SmallAuth.ViewModels.AppManager
{
    public class IndexViewModel
    {
        public List<(string ClientId, string DisplayName, string PostLogoutRedirectUris, string RedirectUris)> AllApplications { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 1)]
        [DataType(DataType.Text)]
        [Display(Name = "Client ID")]
        public string ClientId { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 12)]
        [DataType(DataType.Text)]
        [Display(Name = "Client secret")]
        public string ClientSecret { get; set; } = Guid.NewGuid().ToString();

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 1)]
        [DataType(DataType.Text)]
        [Display(Name = "Display name")]
        public string DisplayName { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 1)]
        [ValidateUriList]
        [DataType(DataType.Text)]
        [Display(Name = "Redirect URIs")]
        public string RedirectUris { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 1)]
        [ValidateUriList]
        [DataType(DataType.Text)]
        [Display(Name = "Post logout redirect URIs")]
        public string PostLogoutRedirectUris { get; set; }
    }
}