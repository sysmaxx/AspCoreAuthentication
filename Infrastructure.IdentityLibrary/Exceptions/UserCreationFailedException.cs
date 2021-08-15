using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class UserCreationFailedException : ApiException
    {
        public UserCreationFailedException()
        {

        }
        public UserCreationFailedException(string msg)
            : base(msg)
        {

        }
    }
}
