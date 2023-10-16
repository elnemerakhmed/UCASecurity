using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Functions
{
    public  class Password
    {
        private static bool HasLowwerCase(string pasword)
        {
            foreach (var ch in pasword)
            {
                if (ch >= 'a' && ch <= 'z')
                    return true;
            }
            return false;
        }
        private static bool HasUpperCase(string pasword)
        {
            foreach (var ch in pasword)
            {
                if (ch >= 'A' && ch <= 'Z')
                    return true;
            }
            return false;
        }
        private static bool HasNumber(string pasword)
        {
            foreach (var ch in pasword)
            {
                if (ch >= '0' && ch <= '9')
                    return true;
            }
            return false;
        }
        private static bool HasNonAlphapticalCharacters(string pasword)
        {
            string spesialChars = @"/*-+_@&$#%)";
            foreach (var ch in pasword)
            {
                if(spesialChars.Contains(ch))
                    return true;
            }
            return false;
        }
        public static Result<string> Strength(string password)
        {
            try
            {
                int counter = 0;
                if (password.Length >= 8)
                {
                    counter++;
                    if (HasLowwerCase(password))
                        counter++;
                    if (HasUpperCase(password))
                        counter++;
                    if (HasNumber(password))
                        counter++;
                    if (HasNonAlphapticalCharacters(password))
                        counter++;
                }

                var percentage = (counter / 5.0) * 100;
                return new Result<string>() { payload = string.Format("{0}%", percentage), status = StatusCode.OK };
            }
            catch (Exception)
            {
                return new Result<string>() { payload = string.Empty, status = StatusCode.Error };
            }
        }
    }
}
