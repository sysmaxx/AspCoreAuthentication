using Infrastructure.EMailLibrary.Models;
using Infrastructure.EMailLibrary.Serivices;
using Infrastructure.IdentityLibrary.Configurations;
using Infrastructure.IdentityLibrary.Context;
using Infrastructure.IdentityLibrary.Exceptions;
using Infrastructure.IdentityLibrary.Models;
using Infrastructure.IdentityLibrary.Models.DTOs;
using Infrastructure.IdentityLibrary.Models.Enums;
using Infrastructure.SharedLibrary.Exceptions;
using Infrastructure.SharedLibrary.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
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
        private readonly JWTSettings _jwtSettings;
        private readonly IdentityContext _identityContext;
        private readonly ICookieService _cookieService;
        private readonly IEmailService _emailService;
        private readonly ILogger<AccountService> _logger;

        public AccountService(
            UserManager<ApplicationUser> userManager,
            IOptions<JWTSettings> jwtSettings,
            IdentityContext identityContext,
            ICookieService cookieService,
            IEmailService emailService,
            ILogger<AccountService> logger
            )
        {
            _userManager = userManager;
            _jwtSettings = jwtSettings.Value;
            _identityContext = identityContext;
            _cookieService = cookieService;
            _emailService = emailService;
            _logger = logger;
        }

        public async Task<ApiResponse<string>> RegisterUserAsync(RegisterUserRequest request, string origin)
        {
            if (await _userManager.FindByNameAsync(request.UserName).ConfigureAwait(false) is not null)
            {
                ApiExceptionBuilder<UsernameTakenException>
                    .Create()
                    .WithMessage("Registration failed")
                    .WithError($"Username '{request.UserName}' is already taken.")
                    .Throw();
            }

            if (await _userManager.FindByEmailAsync(request.EMail).ConfigureAwait(false) is not null)
            {
                ApiExceptionBuilder<EMailTakenException>
                    .Create()
                    .WithMessage("Registration failed")
                    .WithError($"EMail '{request.EMail}' is already taken.")
                    .Throw();
            }

            var user = new ApplicationUser
            {
                Email = request.EMail,
                UserName = request.UserName,
                EmailConfirmed = !_jwtSettings.EmailConfirmationRequired
            };

            var result = await _userManager.CreateAsync(user, request.Password).ConfigureAwait(false);

            if (!result.Succeeded)
            {
                ApiExceptionBuilder<UserCreationFailedException>
                    .Create()
                    .WithMessage("Registration failed")
                    .WithErrors(result.Errors.Select(er => er.Description))
                    .Throw();
            }

            await _userManager.AddToRoleAsync(user, Roles.User.ToString()).ConfigureAwait(false);

            if (_jwtSettings.EmailConfirmationRequired && !await SendVerificationEmailAsync(user, origin).ConfigureAwait(false))
            {
                // Rollback
                await _userManager.DeleteAsync(user).ConfigureAwait(false);

                ApiExceptionBuilder<UserCreationFailedException>
                    .Create()
                    .WithMessage("Registration failed")
                    .WithError("Error while sending verification mail")
                    .Throw();
            }

            return new ApiResponse<string>(user.Email, message: $"User Registered.");
        }

        public async Task<ApiResponse<AuthenticationResponse>> AuthenticateUserAsync(AuthenticationRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email).ConfigureAwait(false)
                ?? throw ApiExceptionBuilder<AccountNotFoundException>
                    .Create()
                    .WithMessage("Authentication failed")
                    .WithError($"Account not found with EMail: '{request.Email}'.")
                    .Build();

            if (!user.EmailConfirmed)
            {
                ApiExceptionBuilder<AccountNotConfirmedException>
                    .Create()
                    .WithMessage("Authentication failed")
                    .WithError($"E-Mail: '{request.Email}' not confirmed.")
                    .Throw();
            }

            if (!await _userManager.CheckPasswordAsync(user, request.Password).ConfigureAwait(false))
            {
                
                // ToDo lockout user for some seconds

                ApiExceptionBuilder<InvalidCredentialsException>
                    .Create()
                    .WithMessage("Authentication failed")
                    .WithError($"Invalid credentials for EMail: '{request.Email}'.")
                    .Throw();
            }

            AuthenticationResponse response = await CreateJwtResponse(user).ConfigureAwait(false);

            return new ApiResponse<AuthenticationResponse>(response, "Authenticated");
        }

        public async Task<ApiResponse<string>> ConfirmEmailAsync(ConfirmEmailRequest request)
        {
            var user = await _userManager.FindByIdAsync(request.UserId).ConfigureAwait(false)
                ?? throw ApiExceptionBuilder<AccountNotFoundException>
                    .Create()
                    .WithMessage("E-Mail confirmation failed")
                    .WithError($"Account not found with Id: '{request.UserId}'.")
                    .Build();

            var token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));

            var confirmation = await _userManager.ConfirmEmailAsync(user, token).ConfigureAwait(false);

            if (!confirmation.Succeeded)
            {
                ApiExceptionBuilder<EmailConfirmationFailedException>
                    .Create()
                    .WithMessage("E-Mail confirmation failed")
                    .WithErrors(confirmation.Errors.Select(er => er.Description))
                    .Throw();
            }

            return new ApiResponse<string>(user.Id, message: $"Account Confirmed for {user.Email}.");
        }

        public async Task<ApiResponse<AuthenticationResponse>> RefreshTokensAsync(RefreshTokenRequest request)
        {
            var userId = GetUserIdFromToken(request.JWToken);

            var user = await _userManager.FindByIdAsync(userId).ConfigureAwait(false)
                ?? throw ApiExceptionBuilder<AccountNotFoundException>
                    .Create()
                    .WithMessage("Refreshing the Tokens failed")
                    .WithError($"Account not found with Id: '{userId}'.")
                    .Build();

            if (_jwtSettings.SaveRefreshTokenInCookie)
                request.RefreshToken = _cookieService.Get(CookieSettings.Name);

            // ToDO: activate lazy loading for RefreshTokens 
            await _identityContext.Entry(user).Collection(t => t.RefreshTokens).LoadAsync().ConfigureAwait(false);
            var refreshToken = user.RefreshTokens.FirstOrDefault(token => token.Token == request.RefreshToken)
                ?? throw ApiExceptionBuilder<RefreshTokenNotFoundException>
                    .Create()
                    .WithMessage("Refreshing the Tokens failed")
                    .WithError($"Token does not exist")
                    .Build();

            if (!refreshToken.IsActive)
            {
                ApiExceptionBuilder<RefreshTokenExpiredException>
                    .Create()
                    .WithMessage("Refreshing the Tokens failed")
                    .WithError($"The token is expired")
                    .Throw();
            }

            refreshToken.Revoked = DateTime.UtcNow;
            await _userManager.UpdateAsync(user).ConfigureAwait(false);

            var response = await CreateJwtResponse(user).ConfigureAwait(false);

            return new ApiResponse<AuthenticationResponse>(response, "Tokens refreshed!");
        }

        public async Task<ApiResponse<string>> RequestResetForgottenPasswordAsync(ForgotPasswordRequest request)
        {
            var response = new ApiResponse<string>(null, "Request successful");
            var user = await _userManager.FindByEmailAsync(request.Email).ConfigureAwait(false);

            // Prevent scanning for registered email addresses
            if (user is null)
            {
                _logger.LogInformation($"Request to reset password for unknown email rejected: {request.Email}");
                return response;
            }

            if (!await SendPasswordRestEmailAsync(user))
            {
                ApiExceptionBuilder<PasswordResetRequestFailedException>
                    .Create()
                    .WithMessage("Password reset failed")
                    .WithError($"Error while sending password reset mail")
                    .Throw();
            }

            return response;
        }

        public async Task<ApiResponse<string>> RestPasswordAsync(RestPasswordRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email).ConfigureAwait(false)
                ?? throw ApiExceptionBuilder<AccountNotFoundException>
                    .Create()
                    .WithMessage("Resetting password failed")
                    .WithError($"Account not found with email: '{request.Email}'.")
                    .Build();

            var token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));

            var result = await _userManager.ResetPasswordAsync(user, token, request.Password).ConfigureAwait(false);

            if (!result.Succeeded)
            {
                ApiExceptionBuilder<PasswordResetFailedException>
                    .Create()
                    .WithMessage("Resetting password failed")
                    .WithErrors(result.Errors.Select(er => er.Description))
                    .Throw();
            }

            // ToDO: activate lazy loading for RefreshTokens 
            await _identityContext.Entry(user).Collection(t => t.RefreshTokens).LoadAsync().ConfigureAwait(false);
            user.RefreshTokens
                .Where(token => token.IsActive).ToList()
                .ForEach(token => token.Revoked = DateTime.UtcNow);

            await _userManager.UpdateAsync(user);

            return new ApiResponse<string>(null, "Reset successful");
        }

        // ToDo: Use string-based tamplate for password rest email
        private async Task<bool> SendPasswordRestEmailAsync(ApplicationUser user)
        {
            var url = await GetPasswordResetUrlAsync(user).ConfigureAwait(false);

            var mail = new EMailRequest
            {
                To = user.Email,
                Subject = "Password rest requested",
                Content = url
            };

            return await _emailService.SendEMailAsync(mail).ConfigureAwait(false);
        }

        // ToDo: Use string-based tamplate for verification email
        private async Task<bool> SendVerificationEmailAsync(ApplicationUser user, string origin)
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
            var token = await GetVerificationTokenAsync(user).ConfigureAwait(false);

            var urlParams = new Dictionary<string, string>
            {
                { VerificationEmailSettings.User, user.Id },
                { VerificationEmailSettings.Token, token }
            };

            var uri = new Uri(origin).Append(_jwtSettings.EmailConfirmationUrl);

            return QueryHelpers.AddQueryString(uri.AbsoluteUri, urlParams);
        }

        private async Task<string> GetPasswordResetUrlAsync(ApplicationUser user)
        {
            var token = await GetPasswordResetTokenAsync(user).ConfigureAwait(false);

            return QueryHelpers.AddQueryString(_jwtSettings.ResetForgottenPasswordUrl, ResetPasswordSettings.ResetToken, token);
        }

        private async Task<string> GetPasswordResetTokenAsync(ApplicationUser user)
            => WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(await _userManager.GeneratePasswordResetTokenAsync(user).ConfigureAwait(false)));

        private async Task<string> GetVerificationTokenAsync(ApplicationUser user)
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

    }
}
