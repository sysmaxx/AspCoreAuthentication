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

        public AccountController(IAccountService accountService)
        {
            _accountService = accountService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync(RegisterUserRequest request)
        {
            var origin = Request.Headers["origin"];
            return Ok(await _accountService.RegisterUserAsync(request, origin));
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> AuthenticateAsync(AuthenticationRequest request)
        {
            return Ok(await _accountService.AuthenticateUserAsync(request));
        }

        [HttpPost("refreshTokens")]
        public async Task<IActionResult> RefreshTokensAsync(RefreshTokenRequest request)
        {
            return Ok(await _accountService.RefreshTokensAsync(request));
        }

        [HttpGet("confirm")]
        public async Task<IActionResult> ConfirmAccountAsync(
            [FromQuery(Name = VerificationEmailSettings.User)] string userId,
            [FromQuery(Name = VerificationEmailSettings.Code)] string code)
        {

            return Ok(await _accountService.ConfirmEmailAsync(userId, code));
        }
    }
}
