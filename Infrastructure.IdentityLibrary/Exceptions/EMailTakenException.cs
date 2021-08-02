using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    class EMailTakenException : Exception
    {
        public EMailTakenException()
        {

        }

        public EMailTakenException(string msg)
            :base(msg)
        {

        }
    }
}
