using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class UsernameTakenException : Exception
    {
        public UsernameTakenException()
        {

        }
        public UsernameTakenException(string msg)
            :base(msg)
        {

        }
    }
}
