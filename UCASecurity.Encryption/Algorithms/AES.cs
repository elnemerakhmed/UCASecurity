using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Algorithms
{
    public class AES : Algorithm<string, string, string>
    {
        public dynamic Algorithm { get; set; }
        public AES(string mode)
        {
            if (mode.StartsWith("AES"))
            {
                Algorithm = new AES1(mode);
            } else
            {
                var algorithmMode = mode.Split('/')[0];
                var paddingMode = mode.Split('/')[0];
                Algorithm = new AES2(algorithmMode, paddingMode);
            }
        }
        public override Result<string> Decrypt(string cipher, string key)
        {
            return Algorithm.Decrypt(cipher, key);
        }

        public override Result<string> Encrypt(string text, string key)
        {
            return Algorithm.Encrypt(text, key);
        }

        public override bool Health()
        {
            return Algorithm.Health();
        }
    }
}
