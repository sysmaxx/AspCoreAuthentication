using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Diagnostics;
using WebApi.Models;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class InfoController : ControllerBase
    {
        [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(ServiceInfo))]
        [HttpGet()]
        public ActionResult<string> Info()
        {
            var assembly = typeof(Startup).Assembly;
            var lastUpdate = System.IO.File.GetLastWriteTime(assembly.Location);
            var version = FileVersionInfo.GetVersionInfo(assembly.Location).ProductVersion;

            return Ok(new ServiceInfo { Version = version, LastUpdate = lastUpdate });
        }
    }
}
