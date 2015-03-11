using System.Web;
using System.Web.Mvc;
using GitHubLogin.Orm;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;

namespace GitHubLogin.Controllers
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
            var properties = new AuthenticationProperties {RedirectUri = RedirectUri};
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
    }
}