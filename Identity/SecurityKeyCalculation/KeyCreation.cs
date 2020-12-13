using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Identity.SecurityKeyCalculation
{
    public static class KeyCreation
    {
        static string GlobalPrivateKeyBase64;

        ///Source: https://stackoverflow.com/questions/17128038/c-sharp-rsa-encryption-decryption-with-transmission
        public static string GenerateKeys()
        {
            //CSP with a new bit rsa key pair
            var csp = new RSACryptoServiceProvider();

            //Private key
            var privKey = csp.ExportParameters(true);

            //Public key
            var pubKey = csp.ExportParameters(false);

            string privKeyString = string.Empty;

            var sw = new System.IO.StringWriter();
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, privKey);
            privKeyString = sw.ToString();

            //This will give public key in the following format which is required by the JS library
            //-----BEGIN PUBLIC KEY-----
            //XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            //-----END PUBLIC KEY-----
            string publicKeyBase64 = ConvertPublicKeyForJS(pubKey);

            //Will be saved in sesssion for later use during decryption
            string privateKeyBase64 = Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(privKeyString));

            GlobalPrivateKeyBase64 = privateKeyBase64;

            //Save in session/temp location
            return publicKeyBase64;
        }


        /// <summary>
        /// Source: https://stackoverflow.com/questions/28406888/c-sharp-rsa-public-key-output-not-correct/28407693#28407693
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static string ConvertPublicKeyForJS(RSAParameters publicKey)
        {
            string output = string.Empty;

            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, publicKey.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, publicKey.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length);

                StringBuilder sb = new StringBuilder();
                sb.AppendLine("-----BEGIN PUBLIC KEY-----");
                sb.AppendLine(base64);
                sb.AppendLine("-----END PUBLIC KEY-----");

                output = sb.ToString();
            }

            return output;
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        private static RSAParameters StringToRSAParameters(string privKeyBase64)
        {

            //string privKeyString = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(privKeyBase64));

            var sr = new System.IO.StringReader(privKeyBase64);
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            return (RSAParameters)xs.Deserialize(sr);

        }

        public static string DecryptValue(string cypherText)
        {
            string plainTextData = string.Empty;

            string privKeyBase64 = GlobalPrivateKeyBase64; //get value from session/temp storage

            string privKeyString = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(privKeyBase64));

            var sr = new System.IO.StringReader(privKeyString);
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            var privKey = (RSAParameters)xs.Deserialize(sr);

            var csp = new RSACryptoServiceProvider();
            csp.ImportParameters(privKey);

            var bytesCypherText = Convert.FromBase64String(cypherText);

            //Problematic line
            var bytesPlainTextData = csp.Decrypt(bytesCypherText, false);

            plainTextData = System.Text.Encoding.Unicode.GetString(bytesPlainTextData);

            return plainTextData;
        }

        public static void Test()
        {
            try
            {
                //Create a UnicodeEncoder to convert between byte array and string.
                UnicodeEncoding ByteConverter = new UnicodeEncoding();

                //Create byte arrays to hold original, encrypted, and decrypted data.
                byte[] dataToEncrypt = ByteConverter.GetBytes("Data to Encrypt");
                byte[] encryptedData;
                byte[] decryptedData;

                //Create a new instance of RSACryptoServiceProvider to generate
                //public and private key data.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Pass the data to ENCRYPT, the public key information 
                    //(using RSACryptoServiceProvider.ExportParameters(false),
                    //and a boolean flag specifying no OAEP padding.
                    encryptedData = RSAEncrypt(dataToEncrypt, RSA.ExportParameters(false), false);

                    //Pass the data to DECRYPT, the private key information 
                    //(using RSACryptoServiceProvider.ExportParameters(true),
                    //and a boolean flag specifying no OAEP padding.
                    decryptedData = RSADecrypt(encryptedData, RSA.ExportParameters(true), false);

                    //Display the decrypted plaintext to the console. 
                    Console.WriteLine("Decrypted plaintext: {0}", ByteConverter.GetString(decryptedData));
                }
            }
            catch (ArgumentNullException)
            {
                //Catch this exception in case the encryption did
                //not succeed.
                Console.WriteLine("Encryption failed.");
            }
        }


        public static void TestKeyAsString()
        {
            try
            {
                //Create a UnicodeEncoder to convert between byte array and string.
                UnicodeEncoding ByteConverter = new UnicodeEncoding();

                //Create byte arrays to hold original, encrypted, and decrypted data.
                byte[] dataToEncrypt = ByteConverter.GetBytes("Data to Encrypt");
                byte[] encryptedData;
                byte[] decryptedData;

                //Create a new instance of RSACryptoServiceProvider to generate
                //public and private key data.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    var publicKey = RSA.ExportParameters(false);
                    var privateKey = RSA.ExportParameters(true);

                    string privKeyString = string.Empty;
                    var swP = new System.IO.StringWriter();
                    var xsP = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    xsP.Serialize(swP, privateKey);
                    privKeyString = swP.ToString();

                    string pubKeyString = string.Empty;
                    var sw = new System.IO.StringWriter();
                    var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                    xs.Serialize(sw, privateKey);
                    pubKeyString = sw.ToString();

                    var returnedpublicKey = StringToRSAParameters(pubKeyString);
                    var returnedprivateKey = StringToRSAParameters(privKeyString);
                    //Pass the data to ENCRYPT, the public key information 
                    //(using RSACryptoServiceProvider.ExportParameters(false),
                    //and a boolean flag specifying no OAEP padding.
                    encryptedData = RSAEncrypt(dataToEncrypt, returnedpublicKey, false);

                    //Pass the data to DECRYPT, the private key information 
                    //(using RSACryptoServiceProvider.ExportParameters(true),
                    //and a boolean flag specifying no OAEP padding.
                    decryptedData = RSADecrypt(encryptedData, returnedprivateKey, false);

                    //Display the decrypted plaintext to the console. 
                    Console.WriteLine("Decrypted plaintext: {0}", ByteConverter.GetString(decryptedData));
                }
            }
            catch (ArgumentNullException)
            {
                //Catch this exception in case the encryption did
                //not succeed.
                Console.WriteLine("Encryption failed.");
            }
        }



        public static string CreateHandshake()
        {

            //CSP with a new bit rsa key pair
            var csp = new RSACryptoServiceProvider();

            //Private key
            var privKey = csp.ExportParameters(true);

            //Public key
            var pubKey = csp.ExportParameters(false);


            //This will give public key in the following format which is required by the JS library
            //-----BEGIN PUBLIC KEY-----
            //XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
            //-----END PUBLIC KEY-----
            string publicKeyBase64 = ConvertPublicKeyForJS(pubKey);

            return "";
        }


        public static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {

                    //Import the RSA Key information. This only needs
                    //toinclude the public key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Encrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);

                return null;
            }
        }

        public static byte[] RSADecrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                //Create a new instance of RSACryptoServiceProvider.
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    //Import the RSA Key information. This needs
                    //to include the private key information.
                    RSA.ImportParameters(RSAKeyInfo);

                    //Decrypt the passed byte array and specify OAEP padding.  
                    //OAEP padding is only available on Microsoft Windows XP or
                    //later.  
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            //Catch and display a CryptographicException  
            //to the console.
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());

                return null;
            }
        }
    }

}
