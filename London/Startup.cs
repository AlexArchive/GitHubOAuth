using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(London.Startup))]
namespace London
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
