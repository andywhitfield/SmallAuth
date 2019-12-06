using Microsoft.AspNetCore.Identity;

namespace SmallAuth.Models
{
    public class ApplicationUser : IdentityUser
    {
        public ApplicationUser()
        {
            LockoutEnabled = true;
        }

        public string DisplayName { get; set; }
    }
}
