using GitHubLogin;
using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Providers.GitHub;

[assembly: OwinStartup(typeof(Startup))]

namespace GitHubLogin
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
            });

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseGitHubAuthentication(new GitHubAuthenticationOptions
            {
                ClientId = "dc2119b9f611c6fec9c6",
                ClientSecret = "d028ee0e40ed333e53efa5dd2aba3e0e56bbfbee",
                Scope = { "" }
            });
        }
    }
}
