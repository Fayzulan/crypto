using Microsoft.AspNetCore.Mvc;

namespace CryptoAPI.Controllers
{
    public class CryptoController : ControllerBase
    {
        protected readonly IConfiguration _Configuration;

        public CryptoController(IConfiguration configuration)
        {
            _Configuration = configuration;
        }
    }
}
