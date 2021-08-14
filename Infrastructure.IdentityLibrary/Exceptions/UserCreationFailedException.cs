using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class UserCreationFailedException : Exception
    {
        public UserCreationFailedException()
        {

        }

        public UserCreationFailedException(string msg)
            :base(msg)
        {

        }  
    }
}
