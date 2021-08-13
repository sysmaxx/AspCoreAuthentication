using System;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class EMailTakenException : Exception
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
