using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace azureAD.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class NewAuthController : ControllerBase
    {
        private readonly LdapService _ldapService;

        public NewAuthController(LdapService ldapService)
        {
            _ldapService = ldapService;
        }

        [HttpPost("validate")]
        public IActionResult ValidateUser([FromBody] LoginModel model)
        {
            if (_ldapService.ValidateUser(model.Username, model.Password))
            {
                return Ok("User is valid");
            }
            else
            {
                return Unauthorized("Invalid username or password");
            }
        }
    }

    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

}
