using JwtAuthDotNet.DTOs;
using JwtAuthDotNet.Entities;
using JwtAuthDotNet.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthDotNet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        private static User user = new User();

        //private readonly IConfiguration configuration;



        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            User user = await authService.RegisterAsync(request);
            if (user == null) {
                return BadRequest("Username already Exists");
            }
            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<TokenResponeDto>> Login(UserDto request)
        {
            var result = await authService.LoginAsync(request);
            if (result is null)
            {
                return BadRequest("Invalid Username or password.");
            }
            return Ok(result);
        }

        [Authorize]
        [HttpGet]
       public IActionResult AuthenticatedEndPoint()
        {
            return Ok("You are authenticated!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("admin-only")]
        public IActionResult AdminOnlyEndPoint()
        {
            return Ok("You are an Admin!");
        }

        [HttpPost("refresh")]
        public async Task<ActionResult<TokenResponeDto>> RefreshToken(RefreshTokenRequestDto request)
        {
            var result = await authService.RefreshTokensAsync(request);

            if (result is null || result.AccessToken is null || result.RefreshToken is null)
            {
                return Unauthorized("Invalid Refresh Token");   
            }

            return Ok(result);
        }
    }
}
