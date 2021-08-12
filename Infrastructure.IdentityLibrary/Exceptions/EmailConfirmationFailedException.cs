using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    class EmailConfirmationFailedException : Exception
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
