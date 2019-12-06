using System.ComponentModel.DataAnnotations;
using SmallAuth.Attributes;

namespace SmallAuth.ViewModels.Manage
{
    public class IndexViewModel
    {
        public string StatusMessage { get; set; }

        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 1)]
        [DataType(DataType.Text)]
        [Display(Name = "Name")]
        public string DisplayName { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Current password")]
        public string Password { get; set; }

        [RequiredWhen(nameof(Password))]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "New password")]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Display(Name = "Confirm new password")]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; }
    }
}
