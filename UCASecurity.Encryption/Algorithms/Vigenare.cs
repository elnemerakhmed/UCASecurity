using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Algorithms
{
	public class Vigenare : Algorithm<string, string, string>
	{
		private static int Mod(int a, int b)
		{
			return (a % b + b) % b;
		}

		private static string Cipher(string input, string key, bool encipher)
		{
			for (int i = 0; i < key.Length; ++i)
				if (!char.IsLetter(key[i]))
					return "Please type valid string .. ";

			string output = string.Empty;
			int nonAlphaCharCount = 0;

			for (int i = 0; i < input.Length; ++i)
			{
				if (char.IsLetter(input[i]))
				{
					bool cIsUpper = char.IsUpper(input[i]);
					char offset = cIsUpper ? 'A' : 'a';
					int keyIndex = (i - nonAlphaCharCount) % key.Length;
					int k = (cIsUpper ? char.ToUpper(key[keyIndex]) : char.ToLower(key[keyIndex])) - offset;
					k = encipher ? k : -k;
					char ch = (char)((Mod(((input[i] + k) - offset), 26)) + offset);
					output += ch;
				}
				else
				{
					output += input[i];
					++nonAlphaCharCount;
				}
			}

			return output;
		}

		public override Result<string> Encrypt(string text, string key)
		{
			try
			{
				string cipher = Cipher(text, key, true);

				return new Result<string>() { status = StatusCode.OK, payload = cipher };
			}
			catch (Exception)
			{
				return new Result<string>() { status = StatusCode.Error, payload = string.Empty };
			}

		}

		public override Result<string> Decrypt(string cipher, string key)
		{
			try
			{
				string text = Cipher(cipher, key, false);

				return new Result<string>() { status = StatusCode.OK, payload = text };
			}
			catch (Exception)
			{
				return new Result<string>() { status = StatusCode.Error, payload = string.Empty };
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
}
