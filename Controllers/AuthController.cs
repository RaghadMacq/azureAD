//using Microsoft.AspNetCore.Authentication;
//using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;

namespace azureAD.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly ITokenAcquisition _tokenAcquisition;

        public AuthController(ITokenAcquisition tokenAcquisition)
        {
            _tokenAcquisition = tokenAcquisition;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequest model)
        {
            if (AuthAgainstAD(model))
            {
                string[] scopes = new string[] { "api://5458ceee-6ee8-4951-923e-7b91c5062a70/.default" };
                string token = await _tokenAcquisition.GetAccessTokenForUserAsync(scopes);
                return Ok(new LoginResponse { Success = true, Token = token });
            }

            return Unauthorized(new LoginResponse { Success = false, Errors = new[] { "INCORRECT_USERNAME_OR_PASSWORD" } });
        }

        private bool AuthAgainstAD(LoginRequest model)
        {
            bool isValid = false;

            try
            {
                using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, "NETORGFT6811883.onmicrosoft.com"))
                {
                    isValid = pc.ValidateCredentials(model.UserName, model.Password);
                }
            }
            catch (Exception e)
            {
                // Log exception
                isValid = false;
            }

            return isValid;
        }
    }
    public class LoginRequest
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }

    public class LoginResponse
    {
        public bool Success { get; set; }
        public string Token { get; set; }
        public string[] Errors { get; set; }
    }
}

