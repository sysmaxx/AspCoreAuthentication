using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class AccountNotConfirmedException : ApiException
    {
        public AccountNotConfirmedException()
        {

        }
        public AccountNotConfirmedException(string msg)
            :base(msg)
        {

        }
    }
}
