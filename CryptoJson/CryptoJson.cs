using Strings;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
#pragma warning disable 618
namespace Security
{
    /// <summary>
    /// The CrytoCredentials are the basis for storing Credentials securely in Source Code/Web.config
    /// </summary>
    public class CryptoJson<T> where T : CryptoJson<T>
    {
        public static X509Certificate2 LoadCert(X509FindType x509FindType, object findValue)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                var cert = store.Certificates.Find(x509FindType, findValue, false).OfType<X509Certificate2>().FirstOrDefault();
                if (cert != null)
                {
                    return cert;
                }
            }
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                return store.Certificates.Find(x509FindType, findValue, false).OfType<X509Certificate2>().FirstOrDefault();
            }
        }

        //internal inmplementation
        private static U Encrypt<U>(Func<RSA, int, U> encryptionFunc, X509Certificate2 certificate)
        {            
            var rsa = certificate.GetRSAPublicKey();
            int chunksize = (rsa.KeySize / 8) - 66; //Asymmetric Encryption using OAEP256: maxLen = KeySize in Bytes - 2*HashSize in Bytes - 2 => KeySize - 2*32 - 2 = Keysize - 66

            return encryptionFunc(rsa, chunksize);
        }

        //internal implementation
        private static T Load(Func<RSA, int, T> decryptFunc, X509Certificate2 certificate)
        {
            var rsa = certificate.GetRSAPrivateKey();
            int chunksize = (rsa.KeySize / 8);
            return decryptFunc(rsa, chunksize);
        }

        /// <summary>
        /// Encrypts the current Object Asymmetrically (RSA OAEP256) into an BASE64 String.<br />
        /// Use <see cref="Load{T}(string)"/> to load this again.
        /// </summary>
        /// <returns>BASE64 encoded RSA encrypted credentials</returns>
        public string ToBase64(X509FindType x509FindType, object findValue)
        {
            var cert = LoadCert(x509FindType, findValue);
            return ToBase64(cert);
        }

        /// <summary>
        /// Encrypts the current Object Asymmetrically (RSA OAEP256) into an BASE64 String.<br />
        /// Use <see cref="Load{T}(string)"/> to load this again.
        /// </summary>
        /// <returns>BASE64 encoded RSA encrypted credentials</returns>
        public string ToBase64(X509Certificate2 certificate)
        {
            return Encrypt((rsa, chunksize) =>
            {
                var json = JsonConvert.SerializeObject(this);
                var bytes = Encoding.UTF8.GetBytes(json);
                int count = bytes.Count();
                List<String> data = new List<String>();
                for (int i = 0; i < count; i = i + chunksize)
                {
                    var buffer = bytes.Skip(i).Take(chunksize).ToArray();
                    data.Add(Convert.ToBase64String(rsa.Encrypt(buffer, RSAEncryptionPadding.OaepSHA256)));
                }
                return StringExtensions.ToStringList(data);
            }, certificate);
        }

        /// <summary>
        /// Encrypts the current Object Asymmetrically (RSA OAEP256) into a bson representation.<br />
        /// Use <see cref="Load{T}(byte[])"/> to load this again.
        /// </summary>
        /// <returns>BSON encoded RSA encrypted credentials</returns>
        public MemoryStream ToBson(X509FindType x509FindType, object findValue)
        {
            var cert = LoadCert(x509FindType, findValue);
            return ToBson(cert);
        }

        /// <summary>
        /// Encrypts the current Object Asymmetrically (RSA OAEP256) into a bson representation.<br />
        /// Use <see cref="Load{T}(byte[])"/> to load this again.
        /// </summary>
        /// <returns>BSON encoded RSA encrypted credentials</returns>
        public MemoryStream ToBson(X509Certificate2 certificate) 
        {
            return Encrypt((rsa, chunksize) =>
            {
                using (MemoryStream mem = new MemoryStream())
                using (BsonWriter bsw = new BsonWriter(mem))
                {
                    JsonSerializer serializer = new JsonSerializer();
                    serializer.Serialize(bsw, this);

                    mem.Position = 0;

                    MemoryStream enc = new MemoryStream((int)Math.Ceiling(mem.Length / (double)chunksize) * (chunksize + 66));
                    using (BinaryReader br = new BinaryReader(mem))
                    {
                        byte[] buffer;
                        while ((buffer = br.ReadBytes(chunksize)).Length > 0)
                        {
                            var encData = rsa.Encrypt(buffer, RSAEncryptionPadding.OaepSHA256);
                            enc.Write(encData,0,encData.Length);
                        }
                        enc.Flush();
                        enc.Position = 0;
                        return enc;
                    }
                }
                
            }, certificate);
        }

        /// <summary>
        /// Loads RSA encrypted BASE64 encoded String of your Object <see cref="ToBase64()"/> 
        /// </summary>
        /// <typeparam name="T">Type of your Credentials.</typeparam>
        /// <param name="encryptedData">BASE64 encoded RSA encrypted json of object</param>
        /// <returns>decrypted credentials</returns>
        public static T Load(X509FindType x509FindType, object findValue, String encryptedData)
        {
            var cert = LoadCert(x509FindType, findValue);
            return Load(cert, encryptedData);
        }

        /// <summary>
        /// Loads RSA encrypted BASE64 encoded String of your Object <see cref="ToBase64()"/> 
        /// </summary>
        /// <typeparam name="T">Type of your Credentials.</typeparam>
        /// <param name="encryptedData">BASE64 encoded RSA encrypted json of object</param>
        /// <returns>decrypted credentials</returns>
        public static T Load(X509Certificate2 certificate, String encryptedData)
        {
            return Load((rsa, chunksize) =>
            {
                List<string> data = encryptedData.ToList();
                using (MemoryStream mem = new MemoryStream(data.Count * chunksize))
                {
                    using (BinaryWriter bw = new BinaryWriter(mem))
                    {
                        foreach (byte[] buffer in data.Select(x => Convert.FromBase64String(x)))
                        {
                            bw.Write(rsa.Decrypt(buffer, RSAEncryptionPadding.OaepSHA256));
                        }
                        bw.Flush();
                        mem.Position = 0;
                        var json = Encoding.UTF8.GetString(mem.ToArray());

                        return JsonConvert.DeserializeObject<T>(json);
                    }
                }
            }, certificate);
        }

        /// <summary>
        /// Loads RSA encrypted BASE64 encoded String of your Object <see cref="ToBase64()"/> 
        /// </summary>
        /// <typeparam name="T">Type of your Credentials.</typeparam>
        /// <param name="encryptedData">BSON encoded RSA encrypted json of object</param>
        /// <returns>decrypted credentials</returns>
        public static T Load(X509FindType x509FindType, object findValue, Stream encryptedData)
        {
            var cert = LoadCert(x509FindType, findValue);
            return Load(cert, encryptedData);
        }

        /// <summary>
        /// Loads RSA encrypted BASE64 encoded String of your Object <see cref="ToBase64()"/> 
        /// </summary>
        /// <typeparam name="T">Type of your Credentials.</typeparam>
        /// <param name="encryptedData">BSON encoded RSA encrypted json of object</param>
        /// <returns>decrypted credentials</returns>
        public static T Load(X509Certificate2 certificate, Stream encryptedData)
        {
            return Load((rsa, chunksize) =>
            {
                using (BinaryReader br = new BinaryReader(encryptedData))
                using (MemoryStream mem = new MemoryStream((int)encryptedData.Length))
                using (BinaryWriter bw = new BinaryWriter(mem))
                {
                    byte[] buffer;
                    while ((buffer = br.ReadBytes(chunksize)).Length == chunksize)
                    {
                        bw.Write(rsa.Decrypt(buffer, RSAEncryptionPadding.OaepSHA256));
                    }
                    bw.Flush();
                    mem.Position = 0;
                    using (BsonReader bsonReader = new BsonReader(mem))
                    {
                        JsonSerializer serializer = new JsonSerializer();
                        return serializer.Deserialize<T>(bsonReader);
                    }
                }
            }, certificate);
        }

    }
}
#pragma warning restore 618

