using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UCASecurity.Encryption.Functions;

namespace UCASecurity.Web.Controllers
{
    public class MathController : Controller
    {
        public IActionResult PrimeFactorization()
        {
            return View();
        }
        [Route("/api/primefactorization")]
        public IActionResult PrimeFactorizationAPI(long number)
        {
            var result = Prime.GetFactors(number);
            return Json(result);
        }
        public IActionResult PrimeTest()
        {
            return View();
        }
        [Route("/api/primetest")]
        public IActionResult PrimeTestAPI(long number)
        {
            var result = Prime.isPrime(number);
            return Json(result);
        }
        public IActionResult GCD()
        {
            return View();
        }
        [Route("/api/gcd")]
        public IActionResult GCDAPI(long a, long b)
        {
            var result = Prime.GCD(a, b);
            return Json(result);
        }
        public IActionResult PasswordStrength()
        {
            return View();
        }
        [Route("/api/passwordstrength")]
        public IActionResult PasswordStrengthAPI(string password)
        {
            var result = Password.Strength(password);
            return Json(result);
        }
    }
}
