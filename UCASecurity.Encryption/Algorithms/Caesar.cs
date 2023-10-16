using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Algorithms
{
    public class Caesar : Algorithm<string, int, string>
    {
        private char cipher(char ch, int key)
        {
            if (!char.IsLetter(ch))
            {
                return ch;
            }
            char d = char.IsUpper(ch) ? 'A' : 'a';
            return (char)((((ch + key) - d) % 26) + d);
        }
        public override Result<string> Decrypt(string cipher, int key)
        {
            try
            {
                int decryptKey = (26 - key) % 26;
                var output = Encrypt(cipher, decryptKey);
                return new Result<string> { status = StatusCode.OK, payload = output.payload };
            }
            catch (Exception)
            {
                return new Result<string> { status = StatusCode.Error, payload = string.Empty };
            }
        }

        public override Result<string> Encrypt(string text, int key)
        {
            try
            {
                string output = string.Empty;
                key %= 26;

                foreach (char ch in text)
                    output += cipher(ch, key);

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
                var cipherResult = Encrypt(Constants.Input, Constants.CEASER_KEY);
                if (cipherResult.status == StatusCode.Error)
                {
                    throw new Exception();
                }
                var textResult = Decrypt(cipherResult.payload, Constants.CEASER_KEY);
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
