using JWTWebAPIExample.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace JWTWebAPIExample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration _config;

        public LoginController(IConfiguration config)
        {

            _config = config;

        }

        private Users AuthenicateUser(Users user)
        {
            Users _user = null;

            if (user.Username == "admin" && user.Password == "12345")
            {
                _user = new Users { Username = "Cameron K" };

            }

            return _user;
        }

        private string GenerateToken(Users users)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(_config["Jwt:Issuer"], _config["Jwt:Audience"], null,
                expires: DateTime.Now.AddMinutes(5),
                signingCredentials: credentials
                );

            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login( Users user)
        {
            IActionResult response = Unauthorized();
            var _user = AuthenicateUser(user);
            if (_user != null)
            {
                var token = GenerateToken(_user);
                response = Ok(new {token = token});
            }

            return response;

        }

    }
}
