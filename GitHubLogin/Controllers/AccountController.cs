using System;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using GitHubLogin.Identity;
using GitHubLogin.Orm;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;

namespace GitHubLogin.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        #region Data
        private ApplicationSignInManager signInManager;
        private ApplicationUserManager userManager;

        private IAuthenticationManager AuthenticationManager
        {
            get { return HttpContext.GetOwinContext().Authentication; }
        }

        public ApplicationSignInManager SignInManager
        {
            get { return signInManager ?? HttpContext.GetOwinContext().Get<ApplicationSignInManager>(); }
            private set { signInManager = value; }
        }

        public ApplicationUserManager UserManager
        {
            get { return userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>(); }
            private set { userManager = value; }
        }
        #endregion

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string returnUrl)
        {
            return new ChallengeResult(
                "GitHub",
                Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var info = await AuthenticationManager.GetExternalLoginInfoAsync();
            var result = await SignInManager.ExternalSignInAsync(info, true);

            if (result == SignInStatus.Success)
            {
                return RedirectToLocal(returnUrl);
            }

            if (result == SignInStatus.Failure)
            {
                var user = new ApplicationUser { UserName = info.DefaultUserName, Email = info.Email };
                var createResult = await UserManager.CreateAsync(user);
                if (createResult.Succeeded)
                {
                    createResult = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (createResult.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
            }

            throw new NotImplementedException("This should not happen.");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (userManager != null)
                {
                    userManager.Dispose();
                    userManager = null;
                }

                if (signInManager != null)
                {
                    signInManager.Dispose();
                    signInManager = null;
                }
            }

            base.Dispose(disposing);
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }
    }
}