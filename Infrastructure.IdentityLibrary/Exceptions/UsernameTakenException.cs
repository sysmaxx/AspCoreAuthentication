using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    class UsernameTakenException : Exception
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
