using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class EmailConfirmationFailedException : Exception
    {
        public EmailConfirmationFailedException()
        {

        }

        public EmailConfirmationFailedException(string msg)
            :base(msg)
        {

        }
    }
}
