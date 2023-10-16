using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UCASecurity.Encryption.Base
{
    public class Result<T>
    {
        public T payload { get; set; }
        public StatusCode status { get; set; }
    }
}
