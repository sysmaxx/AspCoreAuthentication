using Infrastructure.IdentityLibrary.Configurations;
using Infrastructure.IdentityLibrary.Context;
using Infrastructure.IdentityLibrary.Exceptions;
using Infrastructure.IdentityLibrary.Models;
using Infrastructure.IdentityLibrary.Models.DTOs;
using Infrastructure.IdentityLibrary.Models.Enums;
using Infrastructure.SharedLibrary.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.IdentityLibrary.Services
{
    public class AccountService : IAccountService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly JWTSettings _jwtSettings;
        private readonly IdentityContext _identityContext;

        public AccountService(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IOptions<JWTSettings> jwtSettings,
            SignInManager<ApplicationUser> signInManager,
            IdentityContext identityContext
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwtSettings = jwtSettings.Value;
            _signInManager = signInManager;
            _identityContext = identityContext;
        }

        public async Task<ApiResponse<AuthenticationResponse>> AuthenticateUserAsync(AuthenticationRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email).ConfigureAwait(false)
                ?? throw new AccountNotFoundException($"Account not found with EMail: '{request.Email}'.");

            if (!user.EmailConfirmed)
                throw new AccountNotConfirmedException($"E-Mail: '{request.Email}' not confirmed.");

            if (!await _userManager.CheckPasswordAsync(user, request.Password).ConfigureAwait(false))
                throw new InvalidCredentialsException($"Invalid credentials for EMail: '{request.Email}'.");

            var response = new AuthenticationResponse()
            {
                Id = user.Id,
                JWToken = new JwtSecurityTokenHandler().WriteToken(await GenerateJWToken(user).ConfigureAwait(false)),
                Email = user.Email,
                UserName = user.UserName,
                Roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false),
                IsVerified = user.EmailConfirmed,
                RefreshToken = GenerateRefreshToken().Token
            };

            // ToDo: Revoke all activ refreshtokesn
            //       Save new Refreshtoken

            return new ApiResponse<AuthenticationResponse>(response, "Authenticated");
        }

        public async Task<ApiResponse<string>> RegisterUserAsync(RegisterUserRequest request, string origin)
        {
            if (await _userManager.FindByNameAsync(request.UserName).ConfigureAwait(false) is not null)
                throw new UsernameTakenException($"Username '{request.UserName}' is already taken.");

            if (await _userManager.FindByEmailAsync(request.EMail).ConfigureAwait(false) is not null)
                throw new EMailTakenException($"EMail '{request.EMail}' is already taken.");

            var user = new ApplicationUser
            {
                Email = request.EMail,
                UserName = request.UserName,
                // ToDO Verify E-Mail
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, request.Password).ConfigureAwait(false);

            if (!result.Succeeded)
                throw new Exception($"{result.Errors}");

            await _userManager.AddToRoleAsync(user, Roles.User.ToString()).ConfigureAwait(false);

            // ToDo Send E-Mail verification!

            return new ApiResponse<string>(user.Id, message: $"User Registered.");
        }

        private async Task<JwtSecurityToken> GenerateJWToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user).ConfigureAwait(false);
            var roleClaims = (await _userManager.GetRolesAsync(user).ConfigureAwait(false))
                .Select(role => new Claim("roles", role)).ToList();

            var claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id),
            }
            .Union(userClaims)
            .Union(roleClaims);

            return new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)), SecurityAlgorithms.HmacSha256));
        }




        public async Task<ApiResponse<string>> ConfirmEmailAsync(string userId, string code)
        {
            var user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false)
                ?? throw new AccountNotFoundException($"Account not found");

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));

            var result = await _userManager.ConfirmEmailAsync(user, code).ConfigureAwait(false);
            if (!result.Succeeded)
                throw new Exception($"An error occured while confirming {user.Email}.");

            return new ApiResponse<string>(user.Id, message: $"Account Confirmed for {user.Email}. You can now use the /api/Account/authenticate endpoint.");
        }

        private RefreshToken GenerateRefreshToken()
        {
            return new RefreshToken
            {
                Token = RandomTokenString(_jwtSettings.RefreshTokenLength),
                // ToDO: Make expiry configurable
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow
            };
        }

        private static string RandomTokenString(int length)
        {
            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            var randomBytes = new byte[length];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            return BitConverter.ToString(randomBytes).Replace("-", "");
        }


        // ConfirmEMail

        // ResetPassword

        // Revoke Tokens

        // Refresh Tokens
    }
}
