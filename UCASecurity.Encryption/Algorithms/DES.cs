using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Algorithms
{
    public class DES : Algorithm<string, string, string>
    {
        private CipherMode Mode { get; set; }
        private PaddingMode PaddingMode { get; set; }

        public DES(string AlgorithmMode, string PaddingModeName)
        {
            Mode = AlgorithmMode.Equals("CBC") ? CipherMode.CBC : CipherMode.ECB;

            if (PaddingModeName.Equals("PKCS7"))
                PaddingMode = PaddingMode.PKCS7;
            else if (PaddingModeName.Equals("Zeros"))
                PaddingMode = PaddingMode.Zeros;
            else if (PaddingModeName.Equals("ISO10126"))
                PaddingMode = PaddingMode.ISO10126;
        }
        public DES()
        {

        }
        public static byte[] DESCrypto(CryptoOperation cryptoOperation, byte[] IV, byte[] key, byte[] message)
        {
            using (var DES = new DESCryptoServiceProvider())
            {
                DES.IV = IV;
                DES.Key = key;
                DES.Mode = CipherMode.CBC;
                DES.Padding = PaddingMode.PKCS7;


                using (var memStream = new MemoryStream())
                {
                    CryptoStream cryptoStream = null;

                    if (cryptoOperation == CryptoOperation.ENCRYPT)
                        cryptoStream = new CryptoStream(memStream, DES.CreateEncryptor(), CryptoStreamMode.Write);
                    else if (cryptoOperation == CryptoOperation.DECRYPT)
                        cryptoStream = new CryptoStream(memStream, DES.CreateDecryptor(), CryptoStreamMode.Write);

                    if (cryptoStream == null)
                        return null;

                    cryptoStream.Write(message, 0, message.Length);
                    cryptoStream.FlushFinalBlock();
                    return memStream.ToArray();
                }
            }
        }


        public override Result<string> Encrypt(string text, string key)
        {
            try
            {
                byte[] keybytes = Convert.FromBase64String(key);
                byte[] IV = { 12, 4, 8, 55, 1, 7, 5, 25 };

                byte[] encrypted = DESCrypto(CryptoOperation.ENCRYPT, IV, keybytes, Encoding.UTF8.GetBytes(text));
                string output = Convert.ToBase64String(encrypted).Replace("-", "");
                return new Result<string>() { status = StatusCode.OK, payload = output };
            }
            catch (Exception e)
            {
                return new Result<string>() { status = StatusCode.Error, payload = string.Empty };
            }

        }

        public override Result<string> Decrypt(string cipher, string key)
        {
            try
            {
                byte[] keybytes = Convert.FromBase64String(key);
                byte[] IV = { 12, 4, 8, 55, 1, 7, 5, 25 };

                byte[] decrypted = DESCrypto(CryptoOperation.DECRYPT, IV, keybytes, Convert.FromBase64String(cipher));
                string output = Encoding.UTF8.GetString(decrypted);

                return new Result<string>() { status = StatusCode.OK, payload = output };
            }
            catch (Exception e)
            {
                return new Result<string>() { status = StatusCode.Error, payload = string.Empty };
            }
        }

        public override bool Health()
        {
            try
            {
                string key = "AgVOLX0OGhY=";
                var cipherResult = Encrypt(Constants.Input, key);
                if (cipherResult.status == StatusCode.Error)
                {
                    throw new Exception();
                }

                var textResult = Decrypt(cipherResult.payload, key);
                if (textResult.status == StatusCode.Error)
                {
                    throw new Exception();
                }
                return textResult.payload.Equals(Constants.Input);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    public enum CryptoOperation
    {
        ENCRYPT,
        DECRYPT
    };
}
