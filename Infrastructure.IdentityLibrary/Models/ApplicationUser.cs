using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace Infrastructure.IdentityLibrary.Models
{
    public class ApplicationUser : IdentityUser
    {
        public ApplicationUser()
        {
            RefreshTokens = new HashSet<RefreshToken>();
        }

        public virtual ICollection<RefreshToken> RefreshTokens { get; set; }
    }
}
