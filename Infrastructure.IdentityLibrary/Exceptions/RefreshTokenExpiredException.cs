using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    class RefreshTokenExpiredException : Exception
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
