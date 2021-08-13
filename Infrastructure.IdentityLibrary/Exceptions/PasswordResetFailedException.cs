using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class PasswordResetFailedException : Exception
    {
        public PasswordResetFailedException()
        {

        }

        public PasswordResetFailedException(string msg)
            :base(msg)
        {

        }
    }
}
