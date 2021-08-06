using System;

namespace WebApi.Models
{
    public class ServiceInfo
    {
        public string Version { get; set; }
        public DateTime LastUpdate { get; set; }
        public string UserId { get; set; }
    }
}
