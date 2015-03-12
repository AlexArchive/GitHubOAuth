using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Web.Mvc;
using Octokit;

namespace GitHubLoginAdvanced.Controllers
{
    public class HomeController : Controller
    {

        private GitHubClient ResolveClient()
        {
            var identity = (ClaimsIdentity)HttpContext.User.Identity;
            var claims = identity.Claims;
            var accessTokenClaim = claims
                .FirstOrDefault(claim => claim.Type == "urn:tokens:github:accesstoken");

            var client = new GitHubClient(new ProductHeaderValue("GitHubLoginAdvanced"))
            {
                Credentials = new Credentials(accessTokenClaim.Value)
            };
            return client;
        }

        public ViewResult Index()
        {
            if (Request.IsAuthenticated)
            {
                var url = ResolveClient().User.Current().Result.AvatarUrl;
                ViewBag.AvatarUrl = url;
            }

            return View();
        }

        [Authorize]
        public ActionResult UnfollowSzdc()
        {
            ResolveClient().User.Followers.Unfollow("szdc");
            return View("Index");
        }
    }
}