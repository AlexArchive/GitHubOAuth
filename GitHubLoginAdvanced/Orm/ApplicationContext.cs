using Microsoft.AspNet.Identity.EntityFramework;

namespace GitHubLoginAdvanced.Orm
{
    public class ApplicationContext : IdentityDbContext
    {
        public ApplicationContext() : base("GitHubLoginAdvanced")
        {
        }
    }
}