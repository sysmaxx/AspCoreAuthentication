using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    class PasswordResetRequestFaildException : Exception
    {
        public PasswordResetRequestFaildException()
        {

        }

        public PasswordResetRequestFaildException(string msg)
            :base(msg)
        {

        }
    }
}
