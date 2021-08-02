using Infrastructure.IdentityLibrary.Models.DTOs;
using Infrastructure.SharedLibrary.Models;
using System.Threading.Tasks;

namespace Infrastructure.IdentityLibrary.Services
{
    public interface IAccountService
    {
        Task<ApiResponse<AuthenticationResponse>> AuthenticateUserAsync(AuthenticationRequest request);
        Task<ApiResponse<string>> RegisterUserAsync(RegisterUserRequest request, string origin);

        Task<ApiResponse<AuthenticationResponse>> RefreshTokensAsync(RefreshTokenRequest request);
    }
}