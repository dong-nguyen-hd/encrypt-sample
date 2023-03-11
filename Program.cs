
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;

namespace TestMethod
{
    internal static class Program
    {
        static async Task Main()
        {
            Console.WriteLine("Hello, World!");

            using (Aes myAes = Aes.Create())
            {
                //lets take a new CSP with a new 2048 bit rsa key pair
                var csp = new RSACryptoServiceProvider(2048);
                //how to get the private key
                var privKey = csp.ExportParameters(true);
                //and the public key ...
                var pubKey = csp.ExportParameters(false);

                var rawText = "ta quen nhau đã";

                var key = Convert.ToBase64String(myAes.Key);
                var iv = Convert.ToBase64String(myAes.IV);

                var encryptAes = rawText.EncryptDataWithAes(key, iv);
                var cipherTextAes = encryptAes.cipherText;

                var decryptAes = cipherTextAes.DecryptDataWithAes(key, iv);

                Console.WriteLine($"Vector IV: {encryptAes.vectorBase64}\n");
                Console.WriteLine($"Cipher Aes: {encryptAes.cipherText}\n");

                Console.WriteLine($"Plain Text AES: {decryptAes}\n");

                var cipherText = cipherTextAes.EncryptDataWithRSA(pubKey.RSAKeyToString());
                Console.WriteLine($"Cipher text: {cipherText}\n");

                var plainText = cipherText.DecryptDataWithRSA(privKey.RSAKeyToString());
                Console.WriteLine($"Plain text: {plainText}\n");
            }

            Console.ReadKey();
        }

        #region AES
        public static (string cipherText, string vectorBase64) EncryptDataWithAes(this string plainText, string keyBase64, string defaultIV = "")
        {
            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.Key = Convert.FromBase64String(keyBase64);

                if (string.IsNullOrEmpty(defaultIV))
                    aesAlgorithm.GenerateIV();
                else
                    aesAlgorithm.IV = Convert.FromBase64String(defaultIV);

                // Create encryptor object
                ICryptoTransform encryptor = aesAlgorithm.CreateEncryptor();

                byte[] encryptedData;

                // Encryption will be done in a memory stream through a CryptoStream object
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                        encryptedData = ms.ToArray();
                    }
                }

                return (Convert.ToBase64String(encryptedData), Convert.ToBase64String(aesAlgorithm.IV));
            }
        }

        public static string DecryptDataWithAes(this string cipherText, string keyBase64, string vectorBase64)
        {
            using (Aes aesAlgorithm = Aes.Create())
            {
                aesAlgorithm.Key = Convert.FromBase64String(keyBase64);
                aesAlgorithm.IV = Convert.FromBase64String(vectorBase64);

                // Create decryptor object
                ICryptoTransform decryptor = aesAlgorithm.CreateDecryptor();

                byte[] cipher = Convert.FromBase64String(cipherText);

                //Decryption will be done in a memory stream through a CryptoStream object
                using (MemoryStream ms = new MemoryStream(cipher))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
        }
        #endregion

        #region RSA
        public static string RSAKeyToString(this RSAParameters key)
        {
            using (var sw = new StringWriter())
            {
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                xs.Serialize(sw, key);
                return sw.ToString();
            }
        }

        public static RSAParameters StringToRSAKey(this string key)
        {
            using (var sr = new StringReader(key))
            {
                var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));

                return (RSAParameters)xs.Deserialize(sr);
            }
        }

        public static string EncryptDataWithRSA(this string plainText, string publicKey, bool doOAEPPadding = false)
        {
            byte[] encryptedData;
            var tempKey = publicKey.StringToRSAKey();
            var tempPlainBytes = Encoding.Unicode.GetBytes(plainText);

            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                // Import the RSA Key information. This only needs to include the public key information.
                RSA.ImportParameters(tempKey);

                // Encrypt the passed byte array and specify OAEP padding.  
                // OAEP padding is only available on Microsoft Windows XP or later.  
                encryptedData = RSA.Encrypt(tempPlainBytes, doOAEPPadding);
            }

            return Convert.ToBase64String(encryptedData);
        }

        public static string DecryptDataWithRSA(this string cipherText, string privateKey, bool doOAEPPadding = false)
        {
            byte[] decryptedData;
            var tempKey = privateKey.StringToRSAKey();
            var tempCipherBytes = Convert.FromBase64String(cipherText);

            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                // Import the RSA Key information. This needs to include the private key information.
                RSA.ImportParameters(tempKey);

                // Decrypt the passed byte array and specify OAEP padding.  
                // OAEP padding is only available on Microsoft Windows XP or later.  
                decryptedData = RSA.Decrypt(tempCipherBytes, doOAEPPadding);
            }

            return Encoding.Unicode.GetString(decryptedData);
        }
        #endregion
    }
}