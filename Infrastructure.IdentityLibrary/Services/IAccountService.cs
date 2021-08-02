using Infrastructure.IdentityLibrary.Models.DTOs;
using Infrastructure.SharedLibrary.Models;
using System.Threading.Tasks;

namespace Infrastructure.IdentityLibrary.Services
{
    public interface IAccountService
    {
        Task<ApiResponse<AuthenticationResponse>> AuthenticateUserAsync(AuthenticationRequest request);
        Task<ApiResponse<string>> ConfirmEmailAsync(string userId, string code);
        Task<ApiResponse<string>> RegisterUserAsync(RegisterUserRequest request, string origin);
    }
}