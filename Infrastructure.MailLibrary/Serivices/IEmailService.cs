using Infrastructure.EMailLibrary.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace Infrastructure.EMailLibrary.Serivices
{
    public interface IEmailService
    {
        Task SendEMailAsync(EMailRequest mailRequest);
    }
}
