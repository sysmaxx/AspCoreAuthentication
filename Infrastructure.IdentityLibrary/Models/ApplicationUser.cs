using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace Infrastructure.IdentityLibrary.Models
{
    public class ApplicationUser : IdentityUser
    {
        public IEnumerable<RefreshToken> RefreshTokens { get; set; }
    }
}
