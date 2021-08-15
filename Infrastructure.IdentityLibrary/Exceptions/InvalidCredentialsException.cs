using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class InvalidCredentialsException : ApiException
    {
        public InvalidCredentialsException()
        {

        }
        public InvalidCredentialsException(string msg)
            : base(msg)
        {

        }
    }
}
