using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class RefreshTokenNotFoundException : ApiException
    {
        public RefreshTokenNotFoundException()
        {

        }
        public RefreshTokenNotFoundException(string msg)
            : base(msg)
        {

        }
    }
}
