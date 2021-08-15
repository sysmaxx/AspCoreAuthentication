using Infrastructure.SharedLibrary.Exceptions;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class EMailTakenException : ApiException
    {
        public EMailTakenException()
        {

        }
        public EMailTakenException(string msg)
            : base(msg)
        {

        }
    }
}
