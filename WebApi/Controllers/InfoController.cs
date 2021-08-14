using Infrastructure.IdentityLibrary.Services;
using Infrastructure.SharedLibrary.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using WebApi.Models;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class InfoController : ControllerBase
    {

        private readonly IAuthenticatedUserService _authenticatedUserService;

        public InfoController(IAuthenticatedUserService authenticatedUserService)
        {
            _authenticatedUserService = authenticatedUserService;
        }

        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(ApiResponse<ServiceInfo>))]
        [HttpGet()]
        [Authorize(Roles = "User")]
        public ActionResult<string> Info()
        {
            var assembly = typeof(Startup).Assembly;
            var lastUpdate = System.IO.File.GetLastWriteTime(assembly.Location);
            var version = FileVersionInfo.GetVersionInfo(assembly.Location).ProductVersion;

            return Ok(new ApiResponse<ServiceInfo>(new ServiceInfo { Version = version, LastUpdate = lastUpdate, UserId = _authenticatedUserService.UserId }));
        }
    }
}
