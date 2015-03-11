using Microsoft.AspNet.Identity.EntityFramework;

namespace GitHubLogin.Orm
{
    public class ApplicationContext : IdentityDbContext
    {
        public ApplicationContext() : base ("AuthenticateMe")
        {
        }
    }
}