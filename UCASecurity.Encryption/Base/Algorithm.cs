using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UCASecurity.Encryption.Base
{
    public abstract class Algorithm<Input, Key, Result>
    {
        public abstract Result<Result> Encrypt(Input text, Key key);
        public abstract Result<Result> Decrypt(Input cipher, Key key);
        public abstract bool Health();
    }
}
