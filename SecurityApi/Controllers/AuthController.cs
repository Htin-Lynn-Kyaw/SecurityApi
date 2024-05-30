using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SecurityApi.Core.Dtos;
using SecurityApi.Core.Entities;
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
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            bool isOwnerExist = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminExist = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserExist = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerExist && isAdminExist && isUserExist) return Ok("Roles seeding already done.");

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));


            return Ok("Roles seeding complete successfully.");
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var isUserExist = await _userManager.FindByEmailAsync(registerDto.UserName);

            if(isUserExist is not null)
            {
                return BadRequest("User already exist.");
            }

            AppUser newUser = new AppUser()
            {
                FirstName = registerDto.FirstName,
                LastName = registerDto.LastName,
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            var result = await _userManager.CreateAsync(newUser, registerDto.Password);

            if(!result.Succeeded)
            {
                string errorMesaage = "Register failed because :";

                foreach (var error in result.Errors) 
                {
                    errorMesaage += " # " + error.Description;
                }
                return BadRequest(errorMesaage);
            }

            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return Ok("Register successful");
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);
            if (user is null) return BadRequest("Invalid Credentials");

            var isPswCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!isPswCorrect) return BadRequest("Invalid Credentials");

            var userRoles =  await _userManager.GetRolesAsync(user);

            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim("JWTID", Guid.NewGuid().ToString())
            };

            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var token = GenerateJwt(authClaims);

            return Ok(token);
        }

        [HttpPost]
        [Route("promote-user")]
        public async Task<IActionResult> PromoteUser([FromBody] UpdatePermissionDto upDto)
        {
            var user = await _userManager.FindByNameAsync(upDto.UserName);
            if (user is null) return BadRequest("Invalid username.");

            if(upDto.role is "admin")
            {
                await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
            }
            else
            {
                await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);
            }

            return Ok("User is now a/an " + upDto.role);
        }

        private string GenerateJwt(List<Claim> authClaims)
        {
            var screctKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:101101"]!));

            var tokenObj = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(1),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(screctKey, SecurityAlgorithms.HmacSha256)
                );

            return new JwtSecurityTokenHandler().WriteToken(tokenObj);
        }
    }
}
