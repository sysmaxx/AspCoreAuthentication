namespace Infrastructure.IdentityLibrary.Models.DTOs
{
    public class RegisterUserRequest
    {
        public string UserName { get; set; }
        public string EMail { get; set; }
        public string Password { get; set; }
    }
}
