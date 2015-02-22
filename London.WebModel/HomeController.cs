using System.Web.Mvc;

namespace London.WebModel
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return Content("Hello, World.");
        }
    }
}