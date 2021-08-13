namespace Infrastructure.IdentityLibrary.Models.DTOs
{
    public class RestPasswordRequest
    {
        public string Email { get; set; }
        public string Token { get; set; }
        public string Password { get; set; }
    }
}
