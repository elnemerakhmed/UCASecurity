using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Functions
{
    public class SHA256 : Function
    {
        public override Result<string> Hash(string text)
        {
            try
            {
                Sha256Digest digest = new Sha256Digest();
                byte[] scratch = new byte[digest.GetDigestSize()];
                digest.BlockUpdate(UTF8Encoding.UTF8.GetBytes(text), 0, UTF8Encoding.UTF8.GetByteCount(text));
                digest.DoFinal(scratch, 0);
                string hex = BitConverter.ToString(scratch).ToLower().Replace("-", "");
                return new Result<string>() { payload = hex, status = StatusCode.OK };
            }
            catch (Exception)
            {
                return new Result<string>() { payload = string.Empty, status = StatusCode.Error };
            }
        }
    }
}
