using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using GitHubLoginAdvanced.Orm;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;

namespace GitHubLoginAdvanced.Controllers
{
    public class ChallengeResult : HttpUnauthorizedResult
    {
        public string RedirectUri { get; set; }

        public ChallengeResult(string redirectUri)
        {
            RedirectUri = redirectUri;
        }

        public override void ExecuteResult(ControllerContext context)
        {
            var properties = new AuthenticationProperties { RedirectUri = RedirectUri };
            context.HttpContext
                .GetOwinContext()
                .Authentication
                .Challenge(properties, "GitHub");
        }
    }

    public class AccountController : Controller
    {
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login()
        {
            var redirectUri = Url.Action(
                "ExternalLoginCallback",
                "Account");
            return new ChallengeResult(redirectUri);
        }

        public ActionResult ExternalLoginCallback()
        {
            var context = new ApplicationContext();
            var userStore = new UserStore<IdentityUser>(context);
            var userManager = new UserManager<IdentityUser>(userStore);
            var authentication = HttpContext.GetOwinContext().Authentication;
            var signInManager = new SignInManager<IdentityUser, string>(userManager, authentication);
            var account = authentication.GetExternalLoginInfo();
            var status = signInManager.ExternalSignIn(account, false);
            switch (status)
            {
                case SignInStatus.Success:
                    {
                        return RedirectToAction("Index", "Home");
                    }
                case SignInStatus.Failure:
                    {
                        var user = new IdentityUser
                        {
                            UserName = account.DefaultUserName,
                            Email = account.Email
                        };
                        var operation = userManager.Create(user);
                        if (operation.Succeeded)
                        {
                            operation = userManager.AddLogin(user.Id, account.Login);

                            if (operation.Succeeded)
                            {
                                StoreAuthTokenClaims(user);
                                signInManager.SignIn(
                                    user: user,
                                    isPersistent: false,
                                    rememberBrowser: false);
                                return RedirectToAction("Index", "Home");
                            }
                        }
                    }
                    break;
            }
            throw new HttpException(500, "This should not be happening.");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Logout()
        {
            var authentication = HttpContext.GetOwinContext().Authentication;
            authentication.SignOut();
            return RedirectToAction("Index", "Home");
        }

        private void StoreAuthTokenClaims(IdentityUser user)
        {
            var context = new ApplicationContext();
            var userStore = new UserStore<IdentityUser>(context);
            var userManager = new UserManager<IdentityUser>(userStore);
            var authentication = HttpContext.GetOwinContext().Authentication;

            // Get the claims identity
            ClaimsIdentity claimsIdentity =
                authentication.GetExternalIdentity(DefaultAuthenticationTypes.ExternalCookie);

            if (claimsIdentity != null)
            {
                // Retrieve the existing claims
                var currentClaims = userManager.GetClaims(user.Id);

                // Get the list of access token related claims from the identity
                var tokenClaims = claimsIdentity.Claims
                    .Where(c => c.Type.StartsWith("urn:tokens:"));

                // Save the access token related claims
                foreach (var tokenClaim in tokenClaims)
                {
                    if (!currentClaims.Contains(tokenClaim))
                    {
                        userManager.AddClaim(user.Id, tokenClaim);
                    }
                }
            }
        }
    }
}