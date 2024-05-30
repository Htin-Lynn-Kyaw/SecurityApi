using SecurityApi.Core.Dtos;

namespace SecurityApi.Core.Interface
{
    public interface IAuthService
    {
        Task<AuthServiceResponseDto> SeedRoleAsync();
        Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto);
        Task<AuthServiceResponseDto> CreateAsync(LoginDto loginDto);
        Task<AuthServiceResponseDto> PromoteUserAsync(UpdatePermissionDto updatePermissionDto);
    }
}
