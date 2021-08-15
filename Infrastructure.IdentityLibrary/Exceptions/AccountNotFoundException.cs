using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class AccountNotFoundException : ApiException
    {
        public AccountNotFoundException()
        {

        }
        public AccountNotFoundException(string msg)
            : base(msg)
        {

        }
    }
}
