using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class RefreshTokenNotFoundException : Exception
    {
        public RefreshTokenNotFoundException()
        {

        }

        public RefreshTokenNotFoundException(string msg)
            :base(msg)
        {

        }
    }
}
