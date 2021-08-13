using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class RefreshTokenExpiredException : Exception
    {
        public RefreshTokenExpiredException()
        {

        }

        public RefreshTokenExpiredException(string msg)
        :base(msg)
        {

        }

    }
}
