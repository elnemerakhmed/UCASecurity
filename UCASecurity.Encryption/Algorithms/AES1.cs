using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Algorithms
{
    public class AES1 : Algorithm<string, string, string>
	{
        public string Mode { get; set; }
        public AES1(string Mode)
        {
			this.Mode = Mode;
        }
		public static Result<ParametersWithIV> SetUpKey(string key)
		{
			try
			{
				byte[] inputKey = Convert.FromBase64String(key);
				byte[] iv = Hex.Decode("00112233445566778899aabbccddeeff");
				KeyParameter keyParam = ParameterUtilities.CreateKeyParameter("AES", inputKey);
				ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv);
				return new Result<ParametersWithIV>() { status = StatusCode.OK, payload = keyParamWithIV };
			}
			catch (Exception)
			{
				return new Result<ParametersWithIV>() { status = StatusCode.Error, payload = null };
			}
		}
		public override Result<string> Decrypt(string cipher, string key)
		{
			try
			{
				var keyParamWithIv = SetUpKey(key);
				byte[] C = Convert.FromBase64String(cipher);
				IBufferedCipher outCipher = CipherUtilities.GetCipher(Mode);
				outCipher.Init(false, keyParamWithIv.payload);
				byte[] dec = outCipher.DoFinal(C);
				string decryptedInput = Encoding.UTF8.GetString(dec);
				return new Result<string>() { status = StatusCode.OK, payload = decryptedInput };
			}
			catch (Exception e)
			{
				return new Result<string>()
				{
					status = StatusCode.Error,
					payload = string.Empty
				};
			}
		}
		public override Result<string> Encrypt(string text, string key)
		{
			try
			{
				var keyParamWithIv = SetUpKey(key);

				byte[] P = Encoding.UTF8.GetBytes(text);
				IBufferedCipher inCipher = CipherUtilities.GetCipher(Mode);
				inCipher.Init(true, keyParamWithIv.payload);
				byte[] enc = inCipher.DoFinal(P);
				string encryptedInput = Convert.ToBase64String(enc);
				return new Result<string>() { status = StatusCode.OK, payload = encryptedInput };
			}
			catch (Exception e)
			{
				return new Result<string>() { status = StatusCode.Error, payload = string.Empty };
			}
		}
		public override bool Health()
		{
			try
			{
				string key = "FDE8F7A9B86C3BFF07C0D39D04605EDD";
				var cipherResult = Encrypt(Constants.Input, key);
				if (cipherResult.status == StatusCode.Error)
				{
					throw new Exception();
				}

				var textResult = Decrypt(cipherResult.payload, key);
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