namespace Infrastructure.IdentityLibrary.Models.DTOs
{
    public class RefreshTokenRequest
    {
        public string JWToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
