using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class UsernameTakenException : ApiException
    {
        public UsernameTakenException()
        {

        }
        public UsernameTakenException(string msg)
            : base(msg)
        {

        }
    }
}
