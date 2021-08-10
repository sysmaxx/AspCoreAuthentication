using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Infrastructure.EMailLibrary.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static void AddEmailService(this IServiceCollection services, IConfiguration configuration)
        {

        }
    }
}
