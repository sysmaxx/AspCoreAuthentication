using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class AccountNotConfirmedException : Exception
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
