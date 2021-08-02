using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    public class AccountNotFoundException : Exception
    {
        public AccountNotFoundException()
        {

        }

        public AccountNotFoundException(string msg)
            :base(msg)
        {

        }
    }
}
