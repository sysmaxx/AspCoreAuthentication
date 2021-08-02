using Infrastructure.EMailLibrary.Models;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;


namespace Infrastructure.EMailLibrary.Serivices
{
    class EMailServiceDebug : IEmailService
    {
        private readonly ILogger<EMailServiceDebug> _logger;

        public EMailServiceDebug(ILogger<EMailServiceDebug> logger)
        {
            _logger = logger;
        }

        public Task SendEMailAsync(EMailRequest mailRequest)
        {
            _logger.LogInformation($"Email send to: {mailRequest.To} \nsubject: {mailRequest.Subject} \nwith content: {mailRequest.Content}");

            return Task.FromResult(true);
        }
    }
}
