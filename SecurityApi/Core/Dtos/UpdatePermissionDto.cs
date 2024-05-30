using System.ComponentModel.DataAnnotations;

namespace SecurityApi.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "Username is required.")]
        public string UserName { get; set; } = string.Empty;
        [Required(ErrorMessage = "Role is required.")]
        public string role { get; set; } = string.Empty;
    }
}
