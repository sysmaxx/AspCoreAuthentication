namespace Infrastructure.IdentityLibrary.Services
{
    public interface ICookieService
    {
        string Get(string key);
        void Remove(string key);
        void Set(string key, string value, int expireInHours);
    }
}