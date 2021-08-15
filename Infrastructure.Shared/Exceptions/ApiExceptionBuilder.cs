using System.Collections.Generic;
using System.Reflection;

namespace Infrastructure.SharedLibrary.Exceptions
{
    public class ApiExceptionBuilder<TException>  : IThrowableStage<TException>
        where TException : ApiException, new()
    {

        public IEnumerable<string> Errors { get; private set; }

        private readonly TException _exception;

        private ApiExceptionBuilder() 
        {
            _exception = new TException();
        }

        public static IThrowableStage<TException> Create()
        {
            return new ApiExceptionBuilder<TException>();
        }

        public IThrowableStage<TException> WithMessage(string message)
        {
            var flags = BindingFlags.Instance | BindingFlags.NonPublic;
            _exception.GetType().GetField("_message", flags).SetValue(_exception, message);

            return this;
        }

        public IThrowableStage<TException> WithErrors(IEnumerable<string> errors)
        {
            _exception.Errors = errors;
            return this;
        }

        public IThrowableStage<TException> WithError(string error)
        {
            return WithErrors(new List<string> { error });
        }

        public TException Build()
        {
            return _exception;
        }

        public void Throw()
        {
            throw _exception;
        }


    }
}
