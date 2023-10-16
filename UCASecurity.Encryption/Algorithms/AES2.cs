using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Algorithms
{
    public class AES2 : Algorithm<string, string, string>
    {
        private CipherMode Mode { get; set; }
        private PaddingMode PaddingMode { get; set; }
        
        public AES2(string AlgorithmMode, string PaddingModeName)
        {
            Mode = AlgorithmMode.Equals("CBC") ? CipherMode.CBC : CipherMode.ECB;
            if (PaddingModeName.Equals("PKCS7"))
                PaddingMode = PaddingMode.PKCS7;
            else if(PaddingModeName.Equals("Zeros"))
                PaddingMode = PaddingMode.Zeros;
            else if(PaddingModeName.Equals("ISO10126"))
                PaddingMode = PaddingMode.ISO10126;
        }
        public override Result<string> Encrypt(string text, string key)
        {
            try
            {
                var plainBytes = Encoding.UTF8.GetBytes(text);
                string encryptedInput = Convert.ToBase64String(EncryptBytes(plainBytes, getRijndaelManaged(key)));
                return new Result<string>() { status = StatusCode.OK, payload = encryptedInput };
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
                var encryptedBytes = Convert.FromBase64String(cipher);
                string decryptedInput = Encoding.UTF8.GetString(DecryptBytes(encryptedBytes, getRijndaelManaged(key)));
                return new Result<string>() { status = StatusCode.OK, payload = decryptedInput };
            }
            catch (Exception e)
            {
                return new Result<string>()
                {
                    status = StatusCode.Error,
                    payload = string.Empty
                };
            }
        }
        public override bool Health()
        {
            try
            {
                var cipherResult = Encrypt(Constants.Input, Constants.AES_KEY);
                if (cipherResult.status == StatusCode.Error)
                {
                    throw new Exception();
                }

                var textResult = Decrypt(cipherResult.payload, Constants.AES_KEY);
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
        private RijndaelManaged getRijndaelManaged(String secretKey)
        {
            var keyBytes = new byte[16];
            var secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
            Array.Copy(secretKeyBytes, keyBytes, Math.Min(keyBytes.Length, secretKeyBytes.Length));
            return new RijndaelManaged
            {
                Mode = Mode,
                Padding = PaddingMode.ANSIX923,
                KeySize = 128,
                BlockSize = 128,
                Key = keyBytes,
                IV = keyBytes
            };
        }

        private byte[] EncryptBytes(byte[] plainBytes, RijndaelManaged rijndaelManaged)
        {
            return rijndaelManaged.CreateEncryptor()
                .TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        }

        private byte[] DecryptBytes(byte[] encryptedData, RijndaelManaged rijndaelManaged)
        {
            return rijndaelManaged.CreateDecryptor()
                .TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        }

    }
}
