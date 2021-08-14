using System.Collections.Generic;

namespace Infrastructure.SharedLibrary.Models
{
    public class ApiResponse<TResponse> where TResponse : class
    {
        public bool Succeeded { get; set; }
        public string Message { get; set; }
        public IEnumerable<string> Errors { get; set; }
        public TResponse Data { get; set; }

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
