namespace Infrastructure.IdentityLibrary.Services
{
    internal interface ICookieService
    {
        string Get(string key);
        void Remove(string key);
        void Set(string key, string value, int expireInHours);
    }
}