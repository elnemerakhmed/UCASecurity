using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using UCASecurity.Encryption.Algorithms;
using UCASecurity.Web.ViewModels;

namespace UCASecurity.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }
        [Route("/Learn/{id}")]
        public IActionResult Learn(string id)
        {
            var validAlgorithmNames = new List<LearnViewModel>();
            validAlgorithmNames.Add(new LearnViewModel() {  Algorithm = "Caesar", Title = "Algorithms_Caesar_Title", Image = "ceaser.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "Vigenare", Title = "Algorithms_Vigenare_Title", Image = "vigenare.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "PlayFair", Title = "Algorithms_PlayFair_Title", Image = "playfair.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "RailFence", Title = "Algorithms_RailFence_Title", Image = "railfence.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "AES", Title = "Algorithms_AES_Title", Image = "aes.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "DES", Title = "Algorithms_DES_Title", Image = "des.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "BlowFish", Title = "Algorithms_BlowFish_Title", Image = "blowfish.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "RC2", Title = "Algorithms_RC2_Title", Image = "rc2.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "RSA", Title = "Algorithms_RSA_Title", Image = "rsa.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "PasswordStrength", Title = "Math_PasswordStrength_Title", Image = "password.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "PrimeFactorization", Title = "Math_PrimeFactorization_Title", Image = "primefactorization.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "GCD", Title = "Math_GCD_Title", Image = "gcd.png" });
            validAlgorithmNames.Add(new LearnViewModel() { Algorithm = "Hash", Title = "Functions_Hash_Title", Image = "hash.png" });

            var result = validAlgorithmNames.FirstOrDefault(m => m.Algorithm.Equals(id));
            if (result == null)
                return RedirectToAction("Index", "Home");
            return View(result);
        }

        public IActionResult Symmetric()
        {
            var Classic = new List<ItemViewModel>();
            Classic.Add(new ItemViewModel() { Controller = "Algorithms", Action = "Caesar", Title = "Algorithms_Caesar_Title", Healthy = new Caesar().Health(), Image = "ceaser.gif" });
            Classic.Add(new ItemViewModel() { Controller = "Algorithms", Action = "Vigenare", Title = "Algorithms_Vigenare_Title", Healthy = new Vigenare().Health(), Image = "vigenare.gif" });
            Classic.Add(new ItemViewModel() { Controller = "Algorithms", Action = "PlayFair", Title = "Algorithms_PlayFair_Title", Healthy = new PlayFair().Health(), Image = "playfair.gif" });
            Classic.Add(new ItemViewModel() { Controller = "Algorithms", Action = "RailFence", Title = "Algorithms_RailFence_Title", Healthy = new RailFence().Health(), Image = "railfence.gif" });

            var Advanced = new List<ItemViewModel>();
            Advanced.Add(new ItemViewModel() { Controller = "Algorithms", Action = "AES", Title = "Algorithms_AES_Title", Healthy = new AES1("AES/OFB/NoPadding").Health() && new AES2("CBC", "PKCS7").Health(), Image = "aes.gif" });
            Advanced.Add(new ItemViewModel() { Controller = "Algorithms", Action = "DES", Title = "Algorithms_DES_Title", Healthy = new DES("CBC", "PKCS7").Health(), Image = "des.gif" });
            Advanced.Add(new ItemViewModel() { Controller = "Algorithms", Action = "BlowFish", Title = "Algorithms_BlowFish_Title", Healthy = new BlowFish().Health(), Image = "blowfish.gif" });
            Advanced.Add(new ItemViewModel() { Controller = "Algorithms", Action = "RC2", Title = "Algorithms_RC2_Title", Healthy = new RC2().Health(), Image = "rc2.gif" });

            ViewBag.Classic = Classic;
            ViewBag.Advanced = Advanced;
            return View();
        }

        public IActionResult Asymmetric()
        {
            var Asymmetric = new List<ItemViewModel>();
            Asymmetric.Add(new ItemViewModel() { Controller = "Algorithms", Action = "RSA", Title = "Algorithms_RSA_Title", Healthy = new RSA().Health(), Image = "rsa.gif" });

            ViewBag.Asymmetric = Asymmetric;
            return View();
        }
        public IActionResult Math()
        {
            var Math = new List<ItemViewModel>();
            Math.Add(new ItemViewModel() { Controller = "Math", Action = "PasswordStrength", Title = "Math_PasswordStrength_Title", Healthy = true, Image = "password.gif" });
            Math.Add(new ItemViewModel() { Controller = "Math", Action = "PrimeFactorization", Title = "Math_PrimeFactorization_Title", Healthy = true, Image = "factorization.gif" });
            Math.Add(new ItemViewModel() { Controller = "Math", Action = "PrimeTest", Title = "Math_PrimeTest_Title", Healthy = true, HasInfo = false, Image = "primes.gif" });
            Math.Add(new ItemViewModel() { Controller = "Math", Action = "GCD", Title = "Math_GCD_Title", Healthy = true, Image = "gcd.gif" });

            ViewBag.Math = Math;
            return View();
        }
        public IActionResult SetLanguage(string culture, string returnUrl)
        {
            Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture)),
                new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1) }
            );

            return LocalRedirect(returnUrl);
        }

    }
}
