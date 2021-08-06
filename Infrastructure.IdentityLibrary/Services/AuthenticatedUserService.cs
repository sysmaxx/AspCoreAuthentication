using Infrastructure.IdentityLibrary.Models.Enums;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace Infrastructure.IdentityLibrary.Services
{
    public class AuthenticatedUserService : IAuthenticatedUserService
    {

        public string UserId { get; init; }

        public AuthenticatedUserService(IHttpContextAccessor httpContextAccessor)
        {
            UserId = httpContextAccessor.HttpContext?.User?.FindFirstValue(CustomRegisteredClaimNames.UserID);
        }
        
    }
}
