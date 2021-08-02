using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.IdentityLibrary.Exceptions
{
    class RefreshTokenNotFoundException : Exception
    {
        public RefreshTokenNotFoundException()
        {

        }

        public RefreshTokenNotFoundException(string msg)
            :base(msg)
        {

        }
    }
}
