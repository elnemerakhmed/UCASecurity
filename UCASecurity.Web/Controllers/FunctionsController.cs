using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UCASecurity.Encryption.Functions;
using UCASecurity.Web.ViewModels;

namespace UCASecurity.Web.Controllers
{
    public class FunctionsController : Controller
    {
        [Route("/api/hash")]
        public IActionResult HashAPI(string text)
        {
            return Json(new HashFunctionsResultViewModel()
            {
                MD5 = new MD5().Hash(text),
                RIPMED160 = new RIPMED160().Hash(text),
                SHA1 = new SHA1().Hash(text),
                SHA256 = new SHA256().Hash(text),
                SHA512 = new SHA512().Hash(text),
                Tiger = new Tiger().Hash(text),
                Whiirlpool = new Whirlpool().Hash(text)
            });
        }
        public IActionResult Hash()
        {
            return View();
        }
    }
}
