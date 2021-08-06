using Infrastructure.IdentityLibrary.Models;
using Infrastructure.IdentityLibrary.Models.Enums;
using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace Infrastructure.IdentityLibrary.Seeds
{
    public static class DefaultRoles
    {
        public static async Task SeedAsync(RoleManager<IdentityRole> roleManager)
        {
            await roleManager.CreateAsync(new IdentityRole(Roles.Admin));
            await roleManager.CreateAsync(new IdentityRole(Roles.User));
        }
    }
}
