using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class RefreshTokenExpiredException : ApiException
    {
        public RefreshTokenExpiredException()
        {

        }
        public RefreshTokenExpiredException(string msg)
            : base(msg)
        {

        }
    }
}
