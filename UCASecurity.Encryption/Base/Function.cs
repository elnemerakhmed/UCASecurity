using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UCASecurity.Encryption.Base
{
    public abstract class Function
    {
        public abstract Result<string> Hash(string text);
    }
}
