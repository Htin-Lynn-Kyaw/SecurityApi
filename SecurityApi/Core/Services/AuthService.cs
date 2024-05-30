using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using SecurityApi.Core.Dtos;
using SecurityApi.Core.Entities;
using SecurityApi.Core.Interface;
using SecurityApi.Core.Utility;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;

namespace SecurityApi.Core.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<AuthServiceResponseDto> CreateAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.UserName);
            if (user is null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials"
                };
            }

            var isPswCorrect = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!isPswCorrect)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid Credentials"
                };
            }

            var userRoles = await _userManager.GetRolesAsync(user);

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

            return new AuthServiceResponseDto()
            {
                IsSucceed = false,
                Message = token
            };
        }

        public async Task<AuthServiceResponseDto> PromoteUserAsync(UpdatePermissionDto updatePermissionDto)
        {
            var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);
            if (user is null)
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "Invalid username."
                };

            if (updatePermissionDto.role is "admin")
            {
                await _userManager.AddToRoleAsync(user, StaticUserRoles.ADMIN);
            }
            else
            {
                await _userManager.AddToRoleAsync(user, StaticUserRoles.OWNER);
            }

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "User is now a/an " + updatePermissionDto.role
            };
        }

        public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
        {
            var isUserExist = await _userManager.FindByEmailAsync(registerDto.UserName);

            if (isUserExist is not null)
            {
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = "User already exist."
                };
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

            if (!result.Succeeded)
            {
                string errorMesaage = "Register failed because :";

                foreach (var error in result.Errors)
                {
                    errorMesaage += " # " + error.Description;
                }
                return new AuthServiceResponseDto()
                {
                    IsSucceed = false,
                    Message = errorMesaage
                };
            }

            await _userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "Register successful"
            };
        }

        public async Task<AuthServiceResponseDto> SeedRoleAsync()
        {
            bool isOwnerExist = await _roleManager.RoleExistsAsync(StaticUserRoles.OWNER);
            bool isAdminExist = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isUserExist = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isOwnerExist && isAdminExist && isUserExist) 
                return new AuthServiceResponseDto()
                {
                    IsSucceed = true,
                    Message = "Roles seeding already done."
                };

            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.OWNER));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));

            return new AuthServiceResponseDto()
            {
                IsSucceed = true,
                Message = "Roles seeding complete successfully."
            };
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
