using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class EmailConfirmationFailedException : ApiException
    {
        public EmailConfirmationFailedException()
        {

        }
        public EmailConfirmationFailedException(string msg)
            : base(msg)
        {

        }
    }
}
