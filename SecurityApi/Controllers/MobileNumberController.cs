using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using SecurityApi.Core.Utility;

namespace SecurityApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MobileNumberController : ControllerBase
    {
        private readonly string[] phoneNumbers = new[]
        {
            "+959 255283024",
            "+959 792374823",
            "+959 713485923",
            "+959 827345634",
            "+959 674532018",
            "+959 953847265",
            "+959 374652098",
            "+959 628374651",
            "+959 471920384",
            "+959 837465120"
        };

        [HttpGet]
        [Route("GetUser")]
        [Authorize(Roles = StaticUserRoles.USER)]
        public IActionResult GetUser()
        {
            return Ok(phoneNumbers);
        }

        [HttpGet]
        [Route("GetAdmin")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public IActionResult GetAdmin()
        {
            return Ok(phoneNumbers);
        }

        [HttpGet]
        [Route("GetOwner")]
        [Authorize(Roles = StaticUserRoles.OWNER)]
        public IActionResult GetOwner()
        {
            return Ok(phoneNumbers);
        }
    }
}
