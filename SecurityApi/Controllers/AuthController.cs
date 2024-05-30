using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SecurityApi.Core.Dtos;
using SecurityApi.Core.Entities;
using SecurityApi.Core.Interface;
using SecurityApi.Core.Utility;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SecurityApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            var result = await _authService.SeedRoleAsync();
            return Ok(result);
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var result = await _authService.RegisterAsync(registerDto);
            return result.IsSucceed ? Ok(result) : BadRequest(result);
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var result = await _authService.CreateAsync(loginDto);
            return result.IsSucceed ? Ok(result) : BadRequest(result);
        }

        [HttpPost]
        [Route("promote-user")]
        public async Task<IActionResult> PromoteUser([FromBody] UpdatePermissionDto upDto)
        {
            var result = await _authService.PromoteUserAsync(upDto);
            return result.IsSucceed ? Ok(result) : BadRequest(result);
        }
    }
}
