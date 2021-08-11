using Infrastructure.EMailLibrary.Models;
using Infrastructure.EMailLibrary.Serivices;
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
using static Infrastructure.IdentityLibrary.Extensions.UriExtensions;

namespace Infrastructure.IdentityLibrary.Services
{
    public class AccountService : IAccountService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWTSettings _jwtSettings;
        private readonly IdentityContext _identityContext;
        private readonly ICookieService _cookieService;
        private readonly IEmailService _emailService;

        public AccountService(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IOptions<JWTSettings> jwtSettings,
            IdentityContext identityContext,
            ICookieService cookieService,
            IEmailService emailService
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwtSettings = jwtSettings.Value;
            _identityContext = identityContext;
            _cookieService = cookieService;
            _emailService = emailService;
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
                EmailConfirmed = !_jwtSettings.EmailConfirmationRequired
            };

            var result = await _userManager.CreateAsync(user, request.Password).ConfigureAwait(false);

            if (!result.Succeeded)
                throw new Exception($"{result.Errors}");

            await _userManager.AddToRoleAsync(user, Roles.User.ToString()).ConfigureAwait(false);

            if (_jwtSettings.EmailConfirmationRequired & !await SendVerificationEmail(user, origin).ConfigureAwait(false))
            {
                // Rollback
                await _userManager.DeleteAsync(user).ConfigureAwait(false);
                throw new Exception("User registration faild");
            }

            return new ApiResponse<string>(user.Id, message: $"User Registered.");
        }


        public async Task<ApiResponse<AuthenticationResponse>> AuthenticateUserAsync(AuthenticationRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email).ConfigureAwait(false)
                ?? throw new AccountNotFoundException($"Account not found with EMail: '{request.Email}'.");

            if (!user.EmailConfirmed)
                throw new AccountNotConfirmedException($"E-Mail: '{request.Email}' not confirmed.");

            if (!await _userManager.CheckPasswordAsync(user, request.Password).ConfigureAwait(false))
                throw new InvalidCredentialsException($"Invalid credentials for EMail: '{request.Email}'.");

            AuthenticationResponse response = await CreateJwtResponse(user).ConfigureAwait(false);

            return new ApiResponse<AuthenticationResponse>(response, "Authenticated");
        }

        public async Task<ApiResponse<string>> ConfirmEmailAsync(string userId, string code)
        {
            var user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false)
                ?? throw new AccountNotFoundException($"Account not found with Id: '{userId}'.");

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));

            if (!(await _userManager.ConfirmEmailAsync(user, code).ConfigureAwait(false)).Succeeded)
                throw new Exception($"An error occured while confirming {user.Email}.");

            return new ApiResponse<string>(user.Id, message: $"Account Confirmed for {user.Email}.");
        }

        // ToDo: Use string-based tamplate for verification email
        private async Task<bool> SendVerificationEmail(ApplicationUser user, string origin)
        {
            var url = await GetVerificationUrlAsync(user, origin).ConfigureAwait(false);

            var mail = new EMailRequest
            {
                To = user.Email,
                Subject = "Registration",
                Content = url
            };
            return await _emailService.SendEMailAsync(mail).ConfigureAwait(false);
        }

        private async Task<string> GetVerificationUrlAsync(ApplicationUser user, string origin)
        {
            var code = await GetVerificationCodeAsync(user).ConfigureAwait(false);

            var urlParams = new Dictionary<string, string>
            {
                { VerificationEmailSettings.User, user.Id },
                { VerificationEmailSettings.Code, code }
            };

            var uri = new Uri(origin).Append(_jwtSettings.EmailConfirmationUrl);

            return QueryHelpers.AddQueryString(uri.AbsoluteUri, urlParams);
        }

        private async Task<string> GetVerificationCodeAsync(ApplicationUser user)
            => WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(await _userManager.GenerateEmailConfirmationTokenAsync(user).ConfigureAwait(false)));

        private async Task<AuthenticationResponse> CreateJwtResponse(ApplicationUser user)
        {
            var jwtToken = new JwtSecurityTokenHandler().WriteToken(await GenerateJWToken(user).ConfigureAwait(false));
            var roles = await _userManager.GetRolesAsync(user).ConfigureAwait(false);
            var refreshToken = await CreateRefreshToken(user).ConfigureAwait(false);

            if(_jwtSettings.SaveRefreshTokenInCookie)
                _cookieService.Set(CookieSettings.Name, refreshToken.Token, _jwtSettings.RefreshTokenDurationInHours);

            var response = new AuthenticationResponse()
            {
                Id = user.Id,
                JWToken = jwtToken,
                Email = user.Email,
                UserName = user.UserName,
                Roles = roles,
                IsVerified = user.EmailConfirmed,
                RefreshToken = refreshToken.Token,
                RefreshTokenExpiration = refreshToken.Expires
            };
            return response;
        }

        public async Task<ApiResponse<AuthenticationResponse>> RefreshTokensAsync(RefreshTokenRequest request)
        {
            var userId = GetUserIdFromToken(request.JWToken);

            var user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false)
                ?? throw new AccountNotFoundException($"Account not found.");

            if (_jwtSettings.SaveRefreshTokenInCookie)
                request.RefreshToken = _cookieService.Get(CookieSettings.Name);

            // ToDO: activate lazy loading for RefreshTokens 
            await _identityContext.Entry(user).Collection(t => t.RefreshTokens).LoadAsync().ConfigureAwait(false);
            var refreshToken = user.RefreshTokens.FirstOrDefault(token => token.Token == request.RefreshToken) 
                ?? throw new RefreshTokenNotFoundException();

            if (!refreshToken.IsActive)
                throw new RefreshTokenExpiredException();

            refreshToken.Revoked = DateTime.UtcNow;
            await _userManager.UpdateAsync(user).ConfigureAwait(false);

            var response = await CreateJwtResponse(user).ConfigureAwait(false);

            return new ApiResponse<AuthenticationResponse>(response, "Tokens refreshed!");
        }

        private string GetUserIdFromToken(string token)
        {
            var tokenValidationParamters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidateActor = false,
                ValidateLifetime = false,
                ValidIssuer = _jwtSettings.Issuer,
                ValidAudience = _jwtSettings.Audience,
                IssuerSigningKey =
                    new SymmetricSecurityKey(
                        Encoding.ASCII.GetBytes(_jwtSettings.Key))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParamters, out _);

            return principal.FindFirst(CustomRegisteredClaimNames.UserID)?.Value 
                ?? throw new SecurityTokenException($"Missing claim: {CustomRegisteredClaimNames.UserID}");
        }

        private async Task<JwtSecurityToken> GenerateJWToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user).ConfigureAwait(false);
            var roleClaims = (await _userManager.GetRolesAsync(user).ConfigureAwait(false))
                .Select(role => new Claim(CustomRegisteredClaimNames.Roles, role)).ToList();

            var claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(CustomRegisteredClaimNames.UserID, user.Id),
            };

            claims.AddRange(userClaims);
            claims.AddRange(roleClaims);

            return new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key)), SecurityAlgorithms.HmacSha256));
        }


        private async Task<RefreshToken> CreateRefreshToken(ApplicationUser user)
        {
            var token = GenerateRefreshToken();
            user.RefreshTokens.Add(token);
            await _userManager.UpdateAsync(user);
            return token;
        }

        private RefreshToken GenerateRefreshToken()
        {
            return new RefreshToken
            {
                Token = GetRandomHexString(_jwtSettings.RefreshTokenLength),
                Expires = DateTime.UtcNow.AddHours(_jwtSettings.RefreshTokenDurationInHours),
                Created = DateTime.UtcNow
            };
        }

        private static string GetRandomHexString(int length)
        {
            using var cryptoProvider = new RNGCryptoServiceProvider();
            var bytes = new byte[length];
            cryptoProvider.GetBytes(bytes);
            return string.Concat(bytes.Select(b => b.ToString("X2")));
        }


        // ConfirmEMail

        // ResetPassword

        // Add Roles to User
    }
}
