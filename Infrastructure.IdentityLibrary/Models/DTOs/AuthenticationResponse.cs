using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Infrastructure.IdentityLibrary.Models.DTOs
{
    public class AuthenticationResponse
    {
        [JsonIgnore]
        public string Id { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public IEnumerable<string> Roles { get; set; }
        public bool IsVerified { get; set; }
        public string JWToken { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiration { get; set; }

    }
}
