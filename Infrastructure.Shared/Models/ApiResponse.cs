using System.Collections.Generic;

namespace Infrastructure.SharedLibrary.Models
{
    public class ApiResponse<TResponse> where TResponse : class
    {
        public bool Succeeded { get; init; }
        public string Message { get; init; }
        public IEnumerable<string> Errors { get; init; }
        public TResponse Data { get; init; }

        public ApiResponse(TResponse data, string message = null)
        {
            Succeeded = true;
            Message = message;
            Data = data;
        }
        public ApiResponse(string message)
        {
            Succeeded = false;
            Message = message;
        }

    }
}
