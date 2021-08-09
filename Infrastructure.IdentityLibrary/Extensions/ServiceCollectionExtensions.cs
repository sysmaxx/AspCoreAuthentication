using Infrastructure.IdentityLibrary.Configurations;
using Infrastructure.IdentityLibrary.Context;
using Infrastructure.IdentityLibrary.Models;
using Infrastructure.IdentityLibrary.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Infrastructure.IdentityLibrary.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static void AddIdentityInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<IdentityContext>(options => options
            .UseSqlServer(configuration.GetConnectionString("IdentityConnection"), b => b.MigrationsAssembly(typeof(IdentityContext).Assembly.FullName)
                )
            );

            services.AddIdentity<ApplicationUser, IdentityRole>().AddEntityFrameworkStores<IdentityContext>().AddDefaultTokenProviders();

            services.AddTransient<IAccountService, AccountService>();

            services.AddTransient<IAuthenticatedUserService, AuthenticatedUserService>();

            services.Configure<JWTSettings>(configuration.GetSection("JWTSettings"));

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(o =>
                {
                    o.RequireHttpsMetadata = false;
                    o.SaveToken = false;
                    o.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,
                        ValidIssuer = configuration["JWTSettings:Issuer"],
                        ValidAudience = configuration["JWTSettings:Audience"],
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWTSettings:Key"]))
                    };
                    o.Events = new JwtBearerEvents()
                    {
                        OnAuthenticationFailed = context => { return Task.CompletedTask; },
                        //OnAuthenticationFailed = c =>
                        //{
                        //    c.NoResult();
                        //    c.Response.StatusCode = 500;
                        //    c.Response.ContentType = "text/plain";
                        //    return c.Response.WriteAsync(c.Exception.ToString());
                        //},
                        OnChallenge = context =>
                        {
                            context.HandleResponse();
                            context.Response.StatusCode = 401;
                            context.Response.ContentType = "application/json";
                            var result = JsonSerializer.Serialize("You are not Authorized");
                            return context.Response.WriteAsync(result);
                        },
                        OnForbidden = context =>
                        {
                            context.Response.StatusCode = 403;
                            context.Response.ContentType = "application/json";
                            var result = JsonSerializer.Serialize("You are not authorized to access this resource");
                            return context.Response.WriteAsync(result);
                        },
                    };
                });
        }
    }
}
