using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class InvalidCredentialsException : Exception
    {
        public InvalidCredentialsException()
        {

        }

        public InvalidCredentialsException(string msg)
            :base(msg)
        {

        }
    }
}
