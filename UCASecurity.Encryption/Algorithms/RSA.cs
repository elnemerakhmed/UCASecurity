using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Algorithms
{
    public class RSA : Algorithm<string, string, string>
    {
        public static Result<AsymmetricCipherKeyPair> GenerateKeyPair()
        {
            try
            {
                SecureRandom secureRandom = new SecureRandom();
                var keyGenerationParameters = new KeyGenerationParameters(secureRandom, 2048);
                var keyPairGenerator = new RsaKeyPairGenerator();
                keyPairGenerator.Init(keyGenerationParameters);
                var keyPair = keyPairGenerator.GenerateKeyPair();
                return new Result<AsymmetricCipherKeyPair>() { status = StatusCode.OK, payload = keyPair };
            }
            catch (Exception)
            {
                return new Result<AsymmetricCipherKeyPair>() { status = StatusCode.Error, payload = null };
            }
        }
        public static Result<string> KeyToString(AsymmetricKeyParameter key)
        {
            try
            {
                TextWriter textWriter = new StringWriter();
                PemWriter pemWriter = new PemWriter(textWriter);
                pemWriter.WriteObject(key);
                pemWriter.Writer.Flush();
                return new Result<string>() { status = StatusCode.OK, payload = textWriter.ToString() };
            }
            catch (Exception)
            {
                return new Result<string>() { status = StatusCode.Error, payload = string.Empty };
            }
        }
        public static Result<RsaKeyParameters> StringToPublicKey(string key)
        {
            try
            {
                PemReader pemReader = new PemReader(new StringReader(key));
                var pair = (RsaKeyParameters)pemReader.ReadObject();
                return new Result<RsaKeyParameters>() { status = StatusCode.OK, payload = pair };
            }
            catch (Exception)
            {
                return new Result<RsaKeyParameters>() { status = StatusCode.Error, payload = null };
            }
        }
        public static Result<AsymmetricKeyParameter> StringToPrivateKey(string key)
        {
            try
            {
                PemReader pemReader = new PemReader(new StringReader(key));
                var pair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
                return new Result<AsymmetricKeyParameter>() { status = StatusCode.OK, payload = pair.Private };
            }
            catch (Exception)
            {
                return new Result<AsymmetricKeyParameter>() { status = StatusCode.Error, payload = null };
            }
        }
        public override Result<string> Decrypt(string cipher, string key)
        {
            try
            {
                var privateKeyResult = StringToPrivateKey(key);
                if (privateKeyResult.status == StatusCode.Error)
                    throw new ArgumentException();

                var bytes = Convert.FromBase64String(cipher);
                var engine = new Pkcs1Encoding(new RsaEngine());
                engine.Init(false, privateKeyResult.payload);
                var text = Encoding.UTF8.GetString(engine.ProcessBlock(bytes, 0, bytes.Length));
                return new Result<string>() { status = StatusCode.OK, payload = text };
            }
            catch (Exception)
            {
                return new Result<string>() { status = StatusCode.Error, payload = string.Empty };
            }
        }

        public override Result<string> Encrypt(string text, string key)
        {
            try
            {
                var publicKeyResult = StringToPublicKey(key);
                if (publicKeyResult.status == StatusCode.Error)
                    throw new ArgumentException();
                
                var bytes = Encoding.UTF8.GetBytes(text);
                var engine = new Pkcs1Encoding(new RsaEngine());
                engine.Init(true, publicKeyResult.payload);
                var cipher = Convert.ToBase64String(engine.ProcessBlock(bytes, 0, bytes.Length));
                return new Result<string>() { status = StatusCode.OK, payload = cipher };
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
                var keyPairResult = GenerateKeyPair();
                if (keyPairResult.status == StatusCode.Error)
                    throw new Exception();

                var publicKeyResult = KeyToString(keyPairResult.payload.Public);
                if (publicKeyResult.status == StatusCode.Error)
                    throw new Exception();

                var privateKeyResult = KeyToString(keyPairResult.payload.Private);
                if (privateKeyResult.status == StatusCode.Error)
                    throw new Exception();

                var cipherResult = Encrypt(Constants.Input, publicKeyResult.payload);
                if (cipherResult.status == StatusCode.Error)
                    throw new Exception();

                var textResult = Decrypt(cipherResult.payload, privateKeyResult.payload);
                if (textResult.status == StatusCode.Error)
                    throw new Exception();

                return textResult.payload.Equals(Constants.Input);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
