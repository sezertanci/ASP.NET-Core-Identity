using AuthSystem.Areas.Identity.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AuthSystem.Areas.Extensions
{
    public class AppClaimsPrincipalFactory : UserClaimsPrincipalFactory<AuthSystemUser, IdentityRole>
    {
        public AppClaimsPrincipalFactory(
           UserManager<AuthSystemUser> userManager
           , RoleManager<IdentityRole> roleManager
           , IOptions<IdentityOptions> optionsAccessor)
       : base(userManager, roleManager, optionsAccessor)
        { }

        public async override Task<ClaimsPrincipal> CreateAsync(AuthSystemUser user)
        {
            var principal = await base.CreateAsync(user);
            if (!string.IsNullOrWhiteSpace(user.FirstName))
            {
                ((ClaimsIdentity)principal.Identity).AddClaims(new[] { new Claim(ClaimTypes.GivenName, user.FirstName) });
            }

            if (!string.IsNullOrWhiteSpace(user.LastName))
            {
                ((ClaimsIdentity)principal.Identity).AddClaims(new[] { new Claim(ClaimTypes.Surname, user.LastName) });
            }
            return principal;
        }
    }
}
