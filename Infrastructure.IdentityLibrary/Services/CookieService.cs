using Microsoft.AspNetCore.Http;
using System;

namespace Infrastructure.IdentityLibrary.Services
{
    public class CookieService : ICookieService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private IResponseCookies ResponseCookies => _httpContextAccessor.HttpContext.Response.Cookies;
        private IRequestCookieCollection RequestCookies => _httpContextAccessor.HttpContext.Request.Cookies;

        public CookieService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public string Get(string key) => RequestCookies[key];

        public void Set(string key, string value, int expireInHours)
        {
            var option = new CookieOptions
            {
                Expires = DateTime.Now.AddHours(expireInHours)
            };

            ResponseCookies.Append(key, value, option);
        }

        public void Remove(string key) => ResponseCookies.Delete(key);
    }
}
