using System;
using System.Collections.Generic;

namespace Infrastructure.SharedLibrary.Exceptions
{
    public class ApiException : Exception
    {
        public IEnumerable<string> Errors { get; set; }

        public ApiException() { }
        public ApiException(string message) : base(message) { }

    }
}
