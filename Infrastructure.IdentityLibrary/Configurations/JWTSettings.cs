namespace Infrastructure.IdentityLibrary.Configurations
{
    public class JWTSettings
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public double DurationInMinutes { get; set; }

        public int RefreshTokenLength { get; set; }
        public int RefreshTokenDurationInHours { get; set; }
        public bool SaveRefreshTokenInCookie { get; set; }

        public bool EmailConfirmationRequired { get; set; }
        public string EmailConfirmationUrl { get; set; }

        public string ResetForgottenPasswordUrl { get; set; }

    }
}
