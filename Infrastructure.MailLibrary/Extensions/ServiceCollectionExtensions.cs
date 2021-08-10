using Infrastructure.EMailLibrary.Serivices;
using Infrastructure.MailLibrary.Configurations;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;


namespace Infrastructure.EMailLibrary.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static void AddEmailService(this IServiceCollection services, IConfiguration configuration)
        {
            services.Configure<EMailSettings>(configuration.GetSection("EMailSettings"));

            if(bool.Parse(configuration["EMailSettings:Debug"]))
            {
                services.AddScoped<IEmailService, EMailServiceDebug>();
                return;
            }

        }
    }
}
