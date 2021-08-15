using System;
using System.Collections.Generic;

namespace Infrastructure.SharedLibrary.Exceptions
{
    public interface IThrowableStage<TException>
    {
        TException Build();
        void Throw();
        IThrowableStage<TException> WithMessage(string msg);
        IThrowableStage<TException> WithErrors(IEnumerable<string> errors);
        IThrowableStage<TException> WithError(string error);
    }
}
