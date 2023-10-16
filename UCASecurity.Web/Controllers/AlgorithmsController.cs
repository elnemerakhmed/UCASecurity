using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using UCASecurity.Encryption.Algorithms;
using UCASecurity.Web.ViewModels;

namespace UCASecurity.Web.Controllers
{
    public class AlgorithmsController : Controller
    {
        public IActionResult RSA()
        {
            return View();
        }
        [Route("/api/rsa/encrypt")]
        public IActionResult RSAEncrypt(string key, string text)
        {
            var rsa = new RSA();
            var result = rsa.Encrypt(text, key);
            return Json(result);
        }
        [Route("/api/rsa/decrypt")]
        public IActionResult RSADecrypt(string key, string cipher)
        {
            var rsa = new RSA();
            var result = rsa.Decrypt(cipher, key);
            return Json(result);
        }
        public IActionResult GenerateRSAKeyPair()
        {
            var keyPair = Encryption.Algorithms.RSA.GenerateKeyPair();
             
            return View(new RSAKeyPairViewModel() { 
                PublicKey = Encryption.Algorithms.RSA.KeyToString(keyPair.payload.Public).payload,
                PrivateKey = Encryption.Algorithms.RSA.KeyToString(keyPair.payload.Private).payload
            });
        }
        public IActionResult Caesar()
        {
            return View();
        }
        [Route("/api/caesar/encrypt")]
        public IActionResult CaesarEncrypt(int key, string text)
        {
            Caesar ceaser = new Caesar();
            var result = ceaser.Encrypt(text, key);
            return Json(result);
        }

        [Route("/api/caesar/decrypt")]
        public IActionResult CaesarDecrypt(int key, string cipher)
        {
            Caesar ceaser = new Caesar();
            var result = ceaser.Decrypt(cipher, key);
            return Json(result);
        }
        public IActionResult BlowFish()
        {
            return View();
        }
        [Route("/api/blowfish/encrypt")]
        public IActionResult BlowFishEncrypt(string key, string text)
        {
            BlowFish ceaser = new BlowFish();
            var result = ceaser.Encrypt(text, key);
            return Json(result);
        }

        [Route("/api/blowfish/decrypt")]
        public IActionResult BlowFishDecrypt(string key, string cipher)
        {
            BlowFish ceaser = new BlowFish();
            var result = ceaser.Decrypt(cipher, key);
            return Json(result);
        }
        public IActionResult Vigenare()
        {
            return View();
        }
        [Route("/api/vigenare/encrypt")]
        public IActionResult VigenareEncrypt(string key, string text)
        {
            Vigenare vigenare = new Vigenare();
            var result = vigenare.Encrypt(text, key);
            return Json(result);
        }

        [Route("/api/vigenare/decrypt")]
        public IActionResult VigenareDecrypt(string key, string cipher)
        {
            Vigenare vigenare = new Vigenare();
            var result = vigenare.Decrypt(cipher, key);
            return Json(result);
        }
        public IActionResult AES()
        {
            return View();
        }
        [Route("/api/aes/encrypt")]
        public IActionResult AESEncrypt(string key, string text, string mode)
        {
            AES aes = new AES(mode);
            var result = aes.Encrypt(text, key);
            return Json(result);
        }

        [Route("/api/aes/decrypt")]
        public IActionResult AESDecrypt(string key, string cipher, string mode)
        {
            AES aes = new AES(mode);
            var result = aes.Decrypt(cipher, key);
            return Json(result);
        }
        public IActionResult DES()
        {
            return View();
        }
        [Route("/api/des/encrypt")]
        public IActionResult DESEncrypt(string key, string text, string mode)
        {
            var algorithmMode = mode.Split('/')[0];
            var paddingMode = mode.Split('/')[0];
            DES des = new DES(algorithmMode, paddingMode);
            var result = des.Encrypt(text, key);
            return Json(result);
        }

        [Route("/api/des/decrypt")]
        public IActionResult DESDecrypt(string key, string cipher, string mode)
        {
            var algorithmMode = mode.Split('/')[0];
            var paddingMode = mode.Split('/')[0];
            DES des = new DES(algorithmMode, paddingMode);
            var result = des.Decrypt(cipher, key);
            return Json(result);
        }
        public IActionResult RailFence()
        {
            return View();
        }
        [Route("/api/railfence/encrypt")]
        public IActionResult RailFenceEncrypt(int key, string text)
        {
            RailFence railFence = new RailFence();
            var result = railFence.Encrypt(text, key);
            return Json(result);
        }

        [Route("/api/railfence/decrypt")]
        public IActionResult RailFenceDecrypt(int key, string cipher)
        {
            RailFence railFence = new RailFence();
            var result = railFence.Decrypt(cipher, key);
            return Json(result);
        }
        public IActionResult PlayFair()
        {
            return View();
        }

        [Route("/api/playfair/encrypt")]
        public IActionResult PlayFairEncrypt(string key, string text)
        {
            PlayFair playFair = new PlayFair();
            var result = playFair.Encrypt(text, key);
            return Json(result);
        }

        [Route("/api/playfair/decrypt")]
        public IActionResult PlayFairDecrypt(string key, string cipher)
        {
            PlayFair playFair = new PlayFair();
            var result = playFair.Decrypt(cipher, key);
            return Json(result);
        }
        public IActionResult RC2()
        {
            return View();
        }

        [Route("/api/rc2/encrypt")]
        public IActionResult RC2Encrypt(string key, string text)
        {
            RC2 rc2 = new RC2();
            var result = rc2.Encrypt(text, key);
            return Json(result);
        }

        [Route("/api/rc2/decrypt")]
        public IActionResult RC2Decrypt(string key, string cipher)
        {
            RC2 rc2 = new RC2();
            var result = rc2.Decrypt(cipher, key);
            return Json(result);
        }
    }
}
