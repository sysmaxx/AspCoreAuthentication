﻿namespace Infrastructure.IdentityLibrary.Models.DTOs
{
    public class ConfirmEmailRequest
    {
        public string UserId { get; set; }
        public string Token { get; set; }
    }
}
