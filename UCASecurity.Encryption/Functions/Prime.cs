using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Functions
{
    public class Prime
    {
        public static Result<string> GetFactors(long number)
        {
            try
            {
                var primes = new List<long>();

                for (long div = 2; div <= number; div++)
                {
                    while (number % div == 0)
                    {
                        primes.Add(div);
                        number = number / div;
                    }
                }

                string result = string.Join(" x ", primes);
                return new Result<string>() { payload = result, status = StatusCode.OK };
            }
            catch (Exception)
            {
                return new Result<string>() { payload = string.Empty, status = StatusCode.Error };
            }
        }
        public static Result<bool> isPrime(long number)
        {
            try
            {
                if (number == 1) return new Result<bool>() { payload = false, status = StatusCode.OK };
                if (number == 2) return new Result<bool>() { payload = true, status = StatusCode.OK };

                var limit = Math.Ceiling(Math.Sqrt(number));

                for (long i = 2; i <= limit; ++i)
                    if (number % i == 0)
                        return new Result<bool>() { payload = false, status = StatusCode.OK };
                return new Result<bool>() { payload = true, status = StatusCode.OK };
            }
            catch (Exception)
            {
                return new Result<bool>() { payload = false, status = StatusCode.Error };
            }
        }
        private static long GCDHelper(long a, long b)
        {
            return b == 0 ? a : GCDHelper(b, a % b);
        }
        public static Result<long> GCD(long a, long b)
        {
            try
            {
                return new Result<long>() { payload = GCDHelper(a, b), status = StatusCode.OK };

            }
            catch (Exception)
            {
                return new Result<long>() { payload = 0, status = StatusCode.Error };
            }
        }
    }
}
