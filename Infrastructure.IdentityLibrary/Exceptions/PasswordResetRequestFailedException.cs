using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    class PasswordResetRequestFailedException :  ApiException
    {
        public PasswordResetRequestFailedException()
        {

        }
        public PasswordResetRequestFailedException(string msg)
            : base(msg)
        {

        }
    }
}
