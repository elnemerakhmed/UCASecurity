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
    public class RC2 : Algorithm<string, string, string>
    {
        readonly RC2CryptoServiceProvider rc2 = new RC2CryptoServiceProvider();
        byte[] IV = { 2, 5, 95, 36, 56, 1, 2, 3 };
        public override Result<string> Decrypt(string cipher, string key)
        {
            try
            {
                byte[] keybytes = Convert.FromBase64String(key);
                byte[] cipherbytes = Convert.FromBase64String(cipher);
                ICryptoTransform decryptor = rc2.CreateDecryptor(keybytes, IV);
                MemoryStream msDecrypt = new MemoryStream(cipherbytes);
                CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                StringBuilder roundtrip = new StringBuilder();
                int b = 0;
                do
                {
                    b = csDecrypt.ReadByte();
                    if (b != -1)
                    {
                        roundtrip.Append((char)b);
                    }
                } while (b != -1);
                return new Result<string> { status = StatusCode.OK, payload = roundtrip.ToString() };
            }
            catch (Exception e)
            {
                return new Result<string> { status = StatusCode.Error, payload = string.Empty };
            }
        }

        public override Result<string> Encrypt(string text, string key)
        {
            try
            {
                byte[] keybytes = Convert.FromBase64String(key);
                ICryptoTransform encryptor = rc2.CreateEncryptor(keybytes, IV);
                MemoryStream msEncrypt = new MemoryStream();
                CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                byte[] toEncrypt = Encoding.UTF8.GetBytes(text);
                csEncrypt.Write(toEncrypt, 0, toEncrypt.Length);
                csEncrypt.FlushFinalBlock();
                byte[] encrypted = msEncrypt.ToArray();
                string output = Convert.ToBase64String(encrypted);
                return new Result<string> { status = StatusCode.OK, payload = output };
            }
            catch (Exception)
            {
                return new Result<string> { status = StatusCode.Error, payload = string.Empty };
            }
        }

        public override bool Health()
        {
            try
            {
                string key = "AgVOLX0OGhY3V18kOAECAw==";
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
}
