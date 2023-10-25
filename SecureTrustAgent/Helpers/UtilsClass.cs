using NeoLib.Util;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureTrustAgent.Helpers
{
    public class UtilsClass
    {
        string g_strCurrentPath = null;
        string g_strConfigFilePath = null;
        IniFileReadnWrite iniFileReadnWrite;// = new IniFileReadnWrite();

        public UtilsClass()
        {
            g_strCurrentPath = string.Format(@"{0}", System.AppDomain.CurrentDomain.BaseDirectory);
            g_strConfigFilePath = string.Format(@"{0}{1}\{2}", g_strCurrentPath,
                DefineString.PRODDUCT_CONFDIR,
                DefineString.PRODDUCT_CONFFILE);

            iniFileReadnWrite = new IniFileReadnWrite(g_strConfigFilePath);
        }

        public string get_root_dir()
        {
            return g_strCurrentPath;
        }

        public string get_conf_dir()
        {
            return (string.Format(@"{0}\{1}", g_strCurrentPath, DefineString.PRODDUCT_CONFDIR));
        }

        public string get_conf(string key, string section)
        {
            return (iniFileReadnWrite.Read(key, section));
        }

        public void set_conf(string key, string value, string section) { 
            iniFileReadnWrite.Write(key, value, section);
        }
    }

    ///

    public class ProcessStringClass
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="array"></param>
        /// <returns></returns>
        public static string ToHexString(byte[] array)
        {
            StringBuilder hex = new StringBuilder(array.Length * 2);
            foreach (byte b in array)
            {
                hex.AppendFormat("{0:x2}", b);
            }
            return hex.ToString();
        }
    }

    /// <summary>
    /// 
    /// </summary>
    public class ICTK_HASH : ProcessStringClass
    {
        /// <summary>
        /// 
        /// </summary>
        public ICTK_HMAC HMac = new ICTK_HMAC();
        public ICTK_SHA ictk_sha = new ICTK_SHA();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public string hmacSHA256(string key, string data)
        {
            return HMac.HmacSHA256(key, data);
        }

        public string hmacSHA256_v3(string key, string data)
        {
            return HMac.GenerateHMAC(key, data);
        }

        public string hmacSHA256_v2(string key, string data)
        {
            return HMac.HashHMACHex(key, data);
        }




        /// <summary>
        /// 
        /// </summary>
        public class ICTK_HMAC
        {
            /// <summary>
            /// 
            /// </summary>
            /// <param name="key"></param>
            /// <param name="data"></param>
            /// <returns></returns>
            public string HmacSHA256(string key, string data)
            {
                string hash;
                /*ASCIIEncoding encoder = new ASCIIEncoding();
                Byte[] code = encoder.GetBytes(key);
                */
                var hmac_key = Encoding.UTF8.GetBytes(key);

                using (HMACSHA256 hmac = new HMACSHA256(hmac_key))
                {
                    var bytes = Encoding.UTF8.GetBytes(data);
                    string base64 = Convert.ToBase64String(bytes);
                    var message = Encoding.UTF8.GetBytes(base64);
                    Byte[] hmBytes = hmac.ComputeHash(message);
                    hash = ToHexString(hmBytes);
                }
                return hash;
            }

            public string GenerateHMAC(string key, string payload)
            {
                // 키 생성
                var hmac_key = Encoding.UTF8.GetBytes(key);

                // timestamp 생성
                var timeStamp = DateTime.UtcNow;
                var timeSpan = (timeStamp - new DateTime(1970, 1, 1, 0, 0, 0));
                var hmac_timeStamp = (long)timeSpan.TotalMilliseconds;

                // HMAC-SHA256 객체 생성
                using (HMACSHA256 sha = new HMACSHA256(hmac_key))
                {
                    // 본문 생성
                    // 한글이 포함될 경우 글이 깨지는 경우가 생기기 때문에 payload를 base64로 변환 후 암호화를 진행한다.
                    // 타임스탬프와 본문의 내용을 합하여 사용하는 경우가 일반적이다.
                    // 타임스탬프 값을 이용해 호출, 응답 시간의 차이를 구해 invalid를 하거나 accepted를 하는 방식으로 사용가능하다.
                    // 예시에서는 (본문 + 타임스탬프)이지만, 구글링을 통해 찾아보면 (본문 + "^" + 타임스탬프) 등의 방법을 취한다.
                    var bytes = Encoding.UTF8.GetBytes(payload + hmac_timeStamp);
                    string base64 = Convert.ToBase64String(bytes);
                    var message = Encoding.UTF8.GetBytes(base64);

                    // 암호화
                    var hash = sha.ComputeHash(message);

                    // base64 컨버팅
                    return ToHexString(hash);//Convert.ToBase64String(hash);
                }
            }


            public string HashHMACHex(string keyHex, string messageHex)
            {
                /*
                var key = NeoHexString.HexStringToByteArray(keyHex);//Encoding.UTF8.GetBytes(keyHex);
                var message = NeoHexString.HexStringToByteArray(messageHex);//Encoding.UTF8.GetBytes(messageHex);
                var hash = new HMACSHA256(key);
                
                return ToHexString(hash.ComputeHash(message));
                
                //return string.Empty;
                */
                var key = Encoding.UTF8.GetBytes(keyHex);
                var message = Encoding.UTF8.GetBytes(messageHex);
                var hash = new HMACSHA256(key);

                return ToHexString(hash.ComputeHash(message));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public class ICTK_SHA
        {

        }
    }

    /// <summary>
    /// 
    /// </summary>
    public class EncryptionAndDecryption
    {
        /// <summary>
        /// 
        /// </summary>
        ICTK_AES ictk_aes = new ICTK_AES();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cipher"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] aes_decrypt(byte[] cipher, byte[] key)
        {
            return ICTK_AES.AES_Decrypt(cipher, key);
        }


        public class ICTK_AES
        {
            public static byte[] AES_Decrypt(byte[] cipher, byte[] key)
            {
                // Check arguments.
                if (cipher == null || cipher.Length <= 0)
                    throw new ArgumentNullException(nameof(cipher));

                byte[] dycrypted = null;
                using (RijndaelManaged rijAlg = new RijndaelManaged())
                {
                    rijAlg.Mode = CipherMode.CBC;
                    rijAlg.KeySize = key.Length * 8;
                    rijAlg.Key = key;
                    rijAlg.BlockSize = 128;//key.Length * 8;
                    rijAlg.Padding = PaddingMode.Zeros;
                    rijAlg.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                    using (ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV))
                    {
                        using (MemoryStream ms = new MemoryStream(cipher))
                        {
                            using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                            {
                                dycrypted = new byte[cipher.Length];
                                var bytesRead = cryptoStream.Read(dycrypted, 0, cipher.Length);

                                dycrypted = dycrypted.Take(bytesRead).ToArray();
                            }
                        }
                    }
                }

                return dycrypted;
            }
        }


    }
}
