using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using System.Threading.Tasks;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;

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
                using (PrincipalContext pc = new PrincipalContext(ContextType.Domain, "macquires.com")) //NETORGFT6811883.onmicrosoft.com

                {
                    isValid = pc.ValidateCredentials(model.UserName, model.Password);
                }
            }
            catch (PrincipalServerDownException ex)
            {
                // Log specific PrincipalServerDownException
                // Consider using a logging framework like Serilog or NLog for detailed logging
                Console.WriteLine($"PrincipalServerDownException: {ex.Message}");
            }
            catch (LdapException ex)
            {
                // Log specific LdapException
                Console.WriteLine($"LdapException: {ex.Message}");
            }
            catch (Exception ex)
            {
                // Log any other exceptions
                Console.WriteLine($"Exception: {ex.Message}");
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
