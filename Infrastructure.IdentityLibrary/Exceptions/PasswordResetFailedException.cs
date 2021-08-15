using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class PasswordResetFailedException : ApiException
    {
        public PasswordResetFailedException()
        {

        }
        public PasswordResetFailedException(string msg)
            : base(msg)
        {

        }
    }
}
