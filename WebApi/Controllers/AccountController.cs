using Infrastructure.IdentityLibrary.Models.DTOs;
using Infrastructure.IdentityLibrary.Models.Enums;
using Infrastructure.IdentityLibrary.Services;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;


namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly IAccountService _accountService;
        private string Origin => Request.Headers["origin"];

        public AccountController(IAccountService accountService)
        {
            _accountService = accountService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync(RegisterUserRequest request)
        {
            return Ok(await _accountService.RegisterUserAsync(request, Origin).ConfigureAwait(false));
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> AuthenticateAsync(AuthenticationRequest request)
        {
            return Ok(await _accountService.AuthenticateUserAsync(request).ConfigureAwait(false));
        }

        [HttpPost("refreshTokens")]
        public async Task<IActionResult> RefreshTokensAsync(RefreshTokenRequest request)
        {
            return Ok(await _accountService.RefreshTokensAsync(request).ConfigureAwait(false));
        }

        [HttpGet("confirm")]
        public async Task<IActionResult> ConfirmAccountAsync(
            [FromQuery(Name = VerificationEmailSettings.User)] string user,
            [FromQuery(Name = VerificationEmailSettings.Token)] string token)
        {
            var request = new ConfirmEmailRequest { UserId = user, Token = token };
            return Ok(await _accountService.ConfirmEmailAsync(request).ConfigureAwait(false));
        }

        [HttpPost("password-forgot")]
        public async Task<IActionResult> RequestRestPasswordAsync(ForgotPasswordRequest request)
        {
            return Ok(await _accountService.RequestResetForgottenPasswordAsync(request).ConfigureAwait(false));
        }

        [HttpPost("password-reset")]
        public async Task<IActionResult> RestPasswordAsync(RestPasswordRequest request)
        {
            return Ok(await _accountService.RestPasswordAsync(request).ConfigureAwait(false));
        }

        // ToDo: Swagger response documentation
    }
}
