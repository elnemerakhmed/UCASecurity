using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;
using Org.BouncyCastle.Crypto.Parameters;

namespace UCASecurity.Encryption.Algorithms
{
    public class BlowFish : Algorithm<string, string, string>
    {
        public override Result<string> Encrypt(string text, string key)
        {
            try
            {
                BCEngine bcEngine = new BCEngine(new BlowfishEngine(), Encoding.ASCII);
                bcEngine.SetPadding(new Pkcs7Padding());
                string output = bcEngine.Encrypt(text, key);
                return new Result<string> { status = StatusCode.OK, payload = output };
            }
            catch (Exception)
            {
                return new Result<string> { status = StatusCode.Error, payload = string.Empty };
            }
        }

        public override Result<string> Decrypt(string cipher, string key)
        {
            try
            {
                BCEngine bcEngine = new BCEngine(new BlowfishEngine(), Encoding.ASCII);
                bcEngine.SetPadding(new Pkcs7Padding());
                string output = bcEngine.Decrypt(cipher, key);

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
                var cipherResult = Encrypt(Constants.Input, Constants.Input);
                if (cipherResult.status == StatusCode.Error)
                {
                    throw new Exception();
                }

                var textResult = Decrypt(cipherResult.payload, Constants.Input);
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
    public class BCEngine
    {
        private readonly Encoding _encoding;
        private readonly IBlockCipher _blockCipher;
        private Org.BouncyCastle.Crypto.Paddings.PaddedBufferedBlockCipher _cipher;
        private Org.BouncyCastle.Crypto.Paddings.IBlockCipherPadding _padding;

        public BCEngine(IBlockCipher blockCipher, Encoding encoding)
        {
            _blockCipher = blockCipher;
            _encoding = encoding;
        }

        public void SetPadding(IBlockCipherPadding padding)
        {
            if (padding != null)
                _padding = padding;
        }

        public string Encrypt(string plain, string key)
        {
            byte[] result = BouncyCastleCrypto(true, _encoding.GetBytes(plain), key);
            return Convert.ToBase64String(result);
        }

        public string Decrypt(string cipher, string key)
        {
            byte[] result = BouncyCastleCrypto(false, Convert.FromBase64String(cipher), key);
            return _encoding.GetString(result);
        }


        private byte[] BouncyCastleCrypto(bool forEncrypt, byte[] input, string key)
        {
            try
            {
                _cipher = _padding == null ?
                new PaddedBufferedBlockCipher(_blockCipher) : new PaddedBufferedBlockCipher(_blockCipher, _padding);

                int paddingchar = 16 - key.Length;

                for (int i = 0; i < paddingchar; i++)
                {
                    key += " ";
                }
                key = key.Substring(0, 16);

                byte[] keyByte = _encoding.GetBytes(key);


                _cipher.Init(forEncrypt, new KeyParameter(keyByte));
                return _cipher.DoFinal(input);
            }
            catch (Org.BouncyCastle.Crypto.CryptoException ex)
            {
                // throw new CryptoException(ex);
            }
            return null;
        }
    }
}
