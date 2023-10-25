using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.RightsManagement;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Markup;
using Newtonsoft.Json.Serialization;
using pqcclrwrap;
using NeoLib.Util;
using static SecureTrustAgent.Helpers.ictk_puf_warpper;

namespace SecureTrustAgent.Helpers
{
    public class ictk_random : Random
    {
        private static Random r = new Random(DateTime.Now.Millisecond);

        private const string refhex = "0123456789ABCDEF";

        private const string refascii = "0123456789ABCDEFGHJKLMNOPQRSTUVWXYZ!@#$%^&*()abcdefghijklmnopqrstuvwxyz";

        private int m_setFixedLength = -1;

        public bool RandBool => (Next(1) == 1) ? true : false;

        public int FixedLength
        {
            get
            {
                return m_setFixedLength;
            }
            set
            {
                m_setFixedLength = value;
            }
        }

        public static string GetRandAsciiEx(string prfx, string suffix, int size)
        {
            int num = size - prfx.Length - suffix.Length;
            if (num < 0)
            {
                return "";
            }

            return prfx + GetRANDONAscii(num) + suffix;
        }

        public static string GetRandNUM(string refstr, int size)
        {
            string text = "";
            for (int i = 0; i < size; i++)
            {
                text += refstr[r.Next(refstr.Length)];
            }

            return text;
        }

        public static string GetRandHexStr(int size)
        {
            return GetRandNUM("0123456789ABCDEF", 2 * size);
        }

        public static string GetRANDONAscii(int size)
        {
            return GetRandNUM("0123456789ABCDEFGHJKLMNOPQRSTUVWXYZ!@#$%^&*()abcdefghijklmnopqrstuvwxyz", size);
        }

        public byte[] GetRandData(int legth, bool isText)
        {
            return isText ? GetRandText(legth) : GetRandBin(legth);
        }

        public byte[] GetRandBin(int length)
        {
            byte[] array = new byte[length];
            NextBytes(array);
            return array;
        }

        public byte[] GetRandText(int length)
        {
            byte[] array = new byte[length];
            string text = "";
            for (char c = 'a'; c <= 'z'; c = (char)(c + 1))
            {
                text += c;
            }

            for (char c2 = 'A'; c2 <= 'Z'; c2 = (char)(c2 + 1))
            {
                text += c2;
            }

            for (char c3 = '0'; c3 <= '9'; c3 = (char)(c3 + 1))
            {
                text += c3;
            }

            for (int i = 0; i < length; i++)
            {
                if (Next(10) == 0)
                {
                    array[i] = 32;
                }
                else if (Next(20) == 1)
                {
                    array[i] = 10;
                }
                else
                {
                    array[i] = (byte)text[Next(text.Length)];
                }
            }

            return array;
        }
    }
    public class ICTK_ALGORITHM : IDisposable
    {
        public static Byte[] aes_crypto(bool encdec, Byte[] key, Byte[] msg, Byte[] iv)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = 128;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.Zeros;

            var encrypt = encdec ? aes.CreateEncryptor() : aes.CreateDecryptor();

            byte[] ResultArray = encrypt.TransformFinalBlock(msg, 0, msg.Length);

            return (ResultArray != null) ? ResultArray :null;
        }

        public static Byte[] sha_256(Byte[] msg)
        {
            try
            {
                SHA256 mySHA256 = SHA256.Create();

                byte[] hashValue = mySHA256.ComputeHash(msg);
                return (hashValue != null) ? hashValue : null;
            }
            catch 
            {
                return null;
            }
        }

        void IDisposable.Dispose()
        {
            throw new NotImplementedException();
        }
    }

    public class ICTK_PUF : IDisposable
    {
        string ac_key = "52d508da8991f503a08bdce69f0cf72ca1f40abb846a24ded750517dbb80e79b93b72db9e2799d919f44468e53dc194361f8611935c0b91b516da395dbf5c67b";
        public static PqcG3API obj;
        public PqcG3API Obj
        {
            get => obj;
            
            set { obj = value; }
        }

        public bool chipinit()
        {
            if (obj is null)
            {
                return false;
            }

            obj.init();

            return true;
        }

        public bool chipwakeup()
        {
            if (obj is null)
                return false;

            obj.wake_up();

            return true;
        }

        public void chipend()
        {
            if (obj != null)
            {
                try
                {
                    obj.end();
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.Message);
                }

                return;
            }
        }

        public bool ischipconnected()
        {
            bool IsConnected = false;
            if (obj == null)
            {
                return false;
            }

            try
            {
                IsConnected = obj.IsConnected();
                return IsConnected;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            return false;
        }

        public bool set_aes_function(AES_CRYPT aes_crypt, SHA_256 sha_256)
        {
            try
            {
                if (obj is null)
                    return false;

                obj.set_aes_fn(aes_crypt, sha_256);

                return true;
            }
            catch { return false; }
        }

        public string get_chip_serialnumber_for_string()
        {
            if (obj == null)
                return string.Empty;

            try
            {
                var buffer = obj.get_sn();
                if (buffer != null)
                {
                    return NeoHexString.ByteArrayToHexStr(buffer);
                }
                else
                {
                    return string.Empty;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

            return string.Empty;
        }

        public byte[] get_chip_serialnumber_for_byte()
        {
            byte[] sn = null;
            if (obj == null)
                return null;

            try
            {
                sn = obj.get_sn();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

            return sn;
        }

        public string get_chip_challlennge_for_string(int isize)
        {
            try
            {
                if (obj == null) return string.Empty;

                var buffer = obj.get_challenge(isize);
                return (buffer != null) ? STA_HaxString.ByteArrayToHexStr(buffer) : string.Empty;
            }
            catch { }

            return string.Empty;
        }

        public byte[] get_chip_challlennge_for_byte(int isize)
        {
            if (obj == null)
                return null;

            byte[] challenge = null;

            try
            {
                challenge = obj.get_challenge(isize);
            }
            catch { }

            return challenge;
        }

        public bool rest_g3p_chip()
        {
            if (obj == null) return false;

            try
            {
                obj.g3_reset();
                return true;
            }
            catch { }

            return false;
        }

        public bool reset_chip(byte[] challenge, byte[] sign)
        {
            int ret;
            if (obj == null)
                return false;

            try
            {
                string ac_key1 = "52d508da8991f503a08bdce69f0cf72ca1f40abb846a24ded750517dbb80e79b93b72db9e2799d919f44468e53dc194361f8611935c0b91b516da395dbf5c67b";
                ret = obj.reset_puf(2, challenge, sign, NeoHexString.HexStringToByteArray(ac_key1));
                return (ret == 1) ? true : false;
            }
            catch { }

            return false;
        }

        public bool verify_fingerprintf_of_puf()
        {
            int ret;
            if (obj == null)
                return false;

            try
            {
                ValueType buflen = 0;
                byte[] buffer = new byte[4096];
                byte[] tmpbuf = new byte[20];
                byte[] verifyresult = new byte[16];

                ret = obj.FingerPrint_FP_Verify(tmpbuf, ref buflen);
                if (ret < 0)
                    return false;

                Array.Copy(tmpbuf, 1, verifyresult, 0, 16);
                obj.FingerPrint_G3_SetSessionKey(verifyresult);
                return (ret >= 0) ? true : false;
            }
            catch { }

            return false;
        }

        public bool remove_fingerprint_template()
        {
            int ret;

            try
            {
                if (obj == null) return false;

                ret = obj.FingerPrint_G3_RemoveTemplate();

                return (ret >= 0) ? true : false;
            }
            catch { }

            return false;
        }

        public bool macverify_fingerprintf_of_puf()
        {
            int ret = 0;
            if (obj is null)
            {
                return false;
            }
            try
            {
                ValueType buflen = 0;
                byte[] buffer = new byte[4096];
                ret = obj.FingerPrint_G3_MacVerify(buffer, ref buflen);
                if (ret ==0 ) return true;
                
                return false;
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
            }
            return false;
        }

        public byte[] g3berify_fingerprintf_of_puf()
        {
            int ret = 0;
            if (obj is null)
            {
                return null;
            }
            try
            {
                ValueType buflen = 0;
                byte[] buffer = new byte[4096];
                byte[] tmp = new byte[20];
                byte[] G3verifybuffer = new byte[16];
                ret = obj.FingerPrint_G3_Verify(tmp, ref buflen);

                // obj.FingerPrint_G3_SetSessionKey(buffer);
                Array.Copy(tmp, 1, G3verifybuffer, 0, 16);
                obj.FingerPrint_G3_SetSessionKey(G3verifybuffer);
                Console.WriteLine("Session_Key : {0}", NeoHexString.ByteArrayToString(G3verifybuffer));
                return buffer;
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
            }
            return null;
        }

        public bool get_permission_of_puf()
        {
            int ret;

            try
            {
                if (obj == null) return false;

                ValueType valueType = 0;
                byte[] buff = new byte[4096];

                ret = obj.FingerPrint_G3_GetPermission(buff, ref valueType);

                return (ret < 0) ? false : true;
            }
            catch
            {
                return false;
            }
        }

        public bool enroll_fingerprint()
        {
            int ret;

            try
            {
                if (obj == null) return false;

                ret = obj.FingerPrint_G3_Enroll();

                return (ret < 0) ? false : true;

            }catch { }

            return false;
        }

        public bool enrolled_fingerprint()
        {
            int ret;

            try
            {
                if (obj == null) return false;

                ret = obj.FingerPrint_G3_isEnrolled();
                return (ret == 0) ? true : false;
            }catch { }

            return false;
        }

        public bool pqc_kem_enc(byte[] enc_key, byte[] share_key, byte[] pk)
        {
            int ret;

            try
            {
                if (obj == null) return false;

                ret = obj._pqc_wrapper_kem_enc(enc_key, share_key, pk);
                return true;

            }catch { }

            return false;
        }

        public bool pqc_kem_dec(byte[] share_key, byte[] enc_key, byte[] sk)
        {
            int ret;

            try
            {
                ret = obj._pqc_wrapper_kem_dec(share_key, enc_key, sk);
                return true;
            }
            catch  { }

            return false;
        }

        public byte[] pqc_wrapper_sign_signature(byte[] msg, int msgsize, byte[] sk)
        {
            byte[] ret = new byte[3094];

            try
            {
                if(obj == null) return null;

                ret = obj._pqc_wrapper_sign_signature(msg, msgsize, sk);

                return (ret != null)? ret : null;
            }
            catch { }

            return null;
        }

        public bool pqc_wrapper_sig_verify(byte[] sig, int siglen, byte[] msg, int maglen, byte[] pk) 
        {
            int ret;

            try
            {
                if (obj == null) return false;

                ret = obj._pqc_wrapper_sign_verify(sig, (uint)siglen, msg, (uint)maglen, pk);

                return true;
            }catch { }

            return false;
        }

        public byte[]? readbytekey_in_chip(int keyindex, int keyarea)
        {
            if (obj is null)
                return null;

            byte[] readkey = null;

            try
            {
                readkey = obj.read_key(keyindex, keyarea);
                if (readkey != null)
                {
                    return obj.read_key(keyindex, keyarea);
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
            }

            return null;
        }

        public byte[] sign_hmac_in_chip(int index, byte[] msg)
        {
            byte[] readmultikey = null;
            try
            {
                if (obj == null) return null;

                obj.wake_up();
                Thread.Sleep(1);
                readmultikey = obj.sign_hmac(index, msg);

                if (readmultikey == null)
                {
                    obj.wake_up();
                    Thread.Sleep(1);

                    for (int i = 0; i < 3; i++)
                    {
                        readmultikey = obj.sign_hmac(index, msg);
                        if (readmultikey != null)
                        {
                            break;
                        }
                    }
                }

                return (readmultikey != null) ? readmultikey : null;
            }
            catch { }

            return null;
        }

        public byte[] readmultikey_in_chip(int index, int area, int readsize)
        {
            byte[] readmultikey = null;
            try
            {
                if (obj == null) return null;

                obj.wake_up();
                Thread.Sleep(1);
                readmultikey = obj.read_multi_key(index, area, readsize);

                if (readmultikey == null)
                {
                    obj.wake_up();
                    Thread.Sleep(1);

                    for (int i =0; i < 3 ; i++)
                    {
                        readmultikey = obj.read_multi_key(index, area, readsize);
                        if (readmultikey != null)
                        {
                            break;
                        }
                    }
                }

                return (readmultikey !=null) ? readmultikey : null;
            }
            catch { }

            return null;
        }

        void IDisposable.Dispose()
        {
            throw new NotImplementedException();
        }


    }

    public class IctkPufClass 
    {
        public string system_constant = "632854F31C456408B6A3F9B20024EADA";//"4C4755504C55532D5051432D44454D4F2D53595354454D2D434F4E5354414E54";
        ICTK_PUF ictk_puf_api = new ICTK_PUF();
        ICTK_ALGORITHM ictk_algorithm = new ICTK_ALGORITHM();

        static Byte[] aes_crypto(bool encdec, Byte[] key, Byte[] msg, Byte[] iv)
        {
            RijndaelManaged aes = new RijndaelManaged();
            aes.KeySize = 128;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.Zeros;

            var encrypt = encdec ? aes.CreateEncryptor() : aes.CreateDecryptor();

            byte[] ResultArray = encrypt.TransformFinalBlock(msg, 0, msg.Length);

            return ResultArray;
        }
        static Byte[] sha_256(Byte[] msg)
        {
            SHA256 mySHA256 = SHA256.Create();

            byte[] hashValue = mySHA256.ComputeHash(msg);
            return hashValue;
        }

        public bool PqcG3API_FA500InitObject()
        {
            byte[] data = NeoHexString.StringToByteArray(system_constant);
            try
            {
                var pqcApi = new PqcG3API();
                if (pqcApi != null)
                {
                    pqcApi.FA500_init();
                    ictk_puf_api.Obj = pqcApi;

                    pqcApi.set_system_constant(data);
                    pqcApi.set_aes_fn(aes_crypto, sha_256);
                }
                else
                {
                    return false;
                }
            }
            catch {}

            return true;
        }

        

        public bool ispufconnected()
        {
            return ictk_puf_api.ischipconnected() ? true : false;
        }

        public bool set_puf_aes_function(AES_CRYPT aes_crypt, SHA_256 sha_256)
        {
            ictk_puf_api.set_aes_function(aes_crypt, sha_256);
            return true;
        }

        public void puf_end()
        {
            ictk_puf_api.chipend();
        }

        public bool chip_reset_puf(byte[] challlenge, byte[] sign)
        {
            return ictk_puf_api.reset_chip(challlenge, sign);
        }

        public bool puf_g3_set()
        {
            return ictk_puf_api.rest_g3p_chip();
        }

        //remove_fingerprint_template
        public bool remove_fingerprint_template_in_puf()
        {
            return ictk_puf_api.remove_fingerprint_template();
        }

        public string get_challenge_in_puf()
        {
            return ictk_puf_api.get_chip_challlennge_for_string(32);
        }

        public string get_puf_sn_for_string()
        {
            if(ictk_puf_api.chipwakeup() != true) { return string.Empty; }

            if (ictk_puf_api.ischipconnected() != true) { return string.Empty; };

            if (ictk_puf_api.chipwakeup() != true) { return string.Empty; }

            return ictk_puf_api.get_chip_serialnumber_for_string();
        }

        public byte[] get_puf_sn_for_byte()
        {
            if (ictk_puf_api.chipwakeup() != true) { return null; }

            if (ictk_puf_api.ischipconnected() != true) { return null; };

            if (ictk_puf_api.chipwakeup() != true) { return null; }

            return ictk_puf_api.get_chip_serialnumber_for_byte();
        }

        public bool puf_wakeup()
        {
            return (ictk_puf_api.chipwakeup() != true) ? false : true;
        }

        public bool registration_fingerprint()
        {
            return (ictk_puf_api.enroll_fingerprint() != true) ? false : true;
        }

        public bool is_registered_fingerprint()
        {
            return (ictk_puf_api.enrolled_fingerprint() != true) ? false : true;
        }

        public byte[] readbytekey_in_puf(int index, int area)
        {
            return ictk_puf_api.readbytekey_in_chip(index, area);
        }

        public byte[] sign_hmac_in_puf(int keyindex, byte[] input_msg)
        {
            return ictk_puf_api.sign_hmac_in_chip(keyindex, input_msg);
        }

        public byte[] readmultikey_in_puf(int index, int area, int readsize)
        {
            return ictk_puf_api.readmultikey_in_chip(index,area,readsize);
        }

        public byte[] pqc_wrapper_sign_signature(byte[] msg, int msglen, byte[] sk)
        {
            return  ictk_puf_api.pqc_wrapper_sign_signature(msg,msglen, sk);
        }

        public bool pqc_wrapper_sign_verify(byte[] sign, int signlen, byte[] msg, int msglen, byte[] pk)
        {
            return ictk_puf_api.pqc_wrapper_sig_verify(sign, signlen, msg,msglen, pk);
        }

        public bool pqc_kem_enc(byte[] cipher, byte[] sharekey, byte[] publickey)
        {
            return ictk_puf_api.pqc_kem_enc(cipher, sharekey, publickey);
        }

        public bool pqc_kem_dec(byte[] sharekey, byte[] enckey, byte[] skey)
        {
            return ictk_puf_api.pqc_kem_enc(sharekey, enckey, skey);
        }

        //verify_fingerprintf_of_puf

        public bool verif_fingerprint()
        {
            return ictk_puf_api.verify_fingerprintf_of_puf();
        }

    }

    public class ictk_puf_warpper : IDisposable
    {
        IctkPufClass ictkpufclass = new IctkPufClass();
        ICTK_ALGORITHM argorithm = new ICTK_ALGORITHM();
        public ictk_random ictk_rand = new ictk_random();
        //public delegate void DELEGATE_VERIFY(int32_t ret, int32_t data);
        //
        int PUF_KEY_INDEX_HEADER = 15;
        int PUF_KEY_INDEX_PRK = 16;
        int PUF_SECTER_SIZE = 32;
        int PUF_SECTER_PRK_SHA2_SIGNUMHASH = 118;
        int PUF_SECTER_CERT_SHA2_SIGNUMHASH = 119;
        //
        public NeoRandom neo = new NeoRandom();
        //
        public enum P2OPTION
        {
            OPTION_LOWER_SETUP_AREA = 0,
            OPTION_LOWER_KEY_AREA = 1,
            OPTION_LOWER_DATA0_AREA = 2,
            OPTION_LOWER_DATA1_AREA = 3,
        }
        //

        //
        public struct _KEYCERT_HEADER
        {
            public short prk_size;
            public short cert_size;
            public short prk_slot_size;
            public short cert_slot_size;//165
            public short cert_slot2_size;//
            public byte[] dummy = new byte[22];

            public _KEYCERT_HEADER(short prk_size_,
            short cert_size_,
            short prk_slot_size_,
            short cert_slot_size_,//165
            short cert_slot2_size_,//
            byte[] dummy_)// = new byte[22]
            {
                prk_size = prk_size_;
                cert_size = cert_size_;
                prk_slot_size = prk_slot_size_;
                cert_slot_size = cert_slot_size_;//165
                cert_slot2_size = cert_slot2_size_;//
                dummy = dummy_;
            }
        }
        //

        public static T ByteToStruct<T>(byte[] buffer) where T : struct
        {
            T obj = default(T);
            int size = Marshal.SizeOf(typeof(T));
            try
            {
                if (size > buffer.Length)
                {
                    throw new Exception();
                }

                IntPtr ptr = Marshal.AllocHGlobal(size);
                Marshal.Copy(buffer, 0, ptr, size);
                obj = (T)Marshal.PtrToStructure(ptr, typeof(T));
                Marshal.FreeHGlobal(ptr);

                //return obj;
            }
            catch (Exception e)
            {
                Debug.WriteLine("failt to ByteToStruct...");
            }

            return obj;
        }

        public bool isconnect_puf()
        {
            return ictkpufclass.ispufconnected();
        }

        public bool isregistered_fp()
        {
            return ictkpufclass.is_registered_fingerprint();
        }

        public bool init_puf_object()
        {
            return ictkpufclass.PqcG3API_FA500InitObject();
        }

        public string get_rand_string(int length)
        {
            return NeoHexString.ByteArrayToHexStr(ictk_rand.GetRandText(length));
        }

        public bool run_enroll_fingerprint()
        {
            return ictkpufclass.registration_fingerprint();
        }

        public string get_challenge_string_in_puf()
        {
            return ictkpufclass.get_challenge_in_puf();
        }

        public string get_serialnumber_string_in_puf()
        {
            return ictkpufclass.get_puf_sn_for_string();
        }

        public bool verifySHA256chceksumPRK(byte[] prkdata)
        {
            try
            {
                byte[] prkSHA2 = ICTK_ALGORITHM.sha_256(prkdata);
                string sha2 = NeoHexString.ByteArrayToHexStr(prkSHA2);

                byte[] prk_sha2_hash = ictkpufclass.readbytekey_in_puf(PUF_SECTER_PRK_SHA2_SIGNUMHASH, 1);

                if (string.Compare(NeoHexString.ByteArrayToHexStr(prkSHA2),
                    NeoHexString.ByteArrayToHexStr(prk_sha2_hash), true) == 0)
                {
                    return true;
                }
            }
            catch { }
            return false;
        }

        public bool verifySHA256chceksumCert(byte[] certdata)
        {
            try
            {
                byte[] certSHA2 = ICTK_ALGORITHM.sha_256(certdata);
                string sha2 = NeoHexString.ByteArrayToHexStr(certSHA2);
                byte[] cert_sha2_hash = ictkpufclass.readbytekey_in_puf(PUF_SECTER_CERT_SHA2_SIGNUMHASH, 1);

                if (string.Compare (NeoHexString.ByteArrayToHexStr(certSHA2),
                    NeoHexString.ByteArrayToHexStr (cert_sha2_hash), true) == 0) {
                    return true;
                }
            }
            catch { }
            return false;
        }

        public byte[] getbyteprk_in_puf()
        {
            try
            {
                if (ictkpufclass.ispufconnected() == true)
                {
                    if (!ictkpufclass.set_puf_aes_function(ICTK_ALGORITHM.aes_crypto, ICTK_ALGORITHM.sha_256))
                    {
                        return null;
                    }

                    ictkpufclass.puf_wakeup();
                    byte[] readbuf = ictkpufclass.readbytekey_in_puf(15, 1);
                    if (readbuf == null) { return null; }

                    _KEYCERT_HEADER KeyCertHeader = ByteToStruct<_KEYCERT_HEADER>(readbuf);

                    byte[] prkdata = ictkpufclass.readmultikey_in_puf(PUF_KEY_INDEX_PRK,
                        (int)P2OPTION.OPTION_LOWER_KEY_AREA,
                        (int)KeyCertHeader.prk_size);

                    if (verifySHA256chceksumPRK(prkdata) == false)
                    {
                        return null;
                    }

                    return (prkdata!= null) ? prkdata : null;
                }
                else                {
                    return null;
                }
            }catch { return null; }
        }

        public bool chk_hmac_sign(string ac_type)
        {
            var chal_admin = NeoHexString.StringToByteArray("237C386D9E3B8F31AFD4C721400EB708E16625FBC6B42D9D5F4AF7C8626AF5B9");
            var expect_hmac_sign_admin = NeoHexString.StringToByteArray("4E9DE43E7B10B95A08A912EA871341B262438EBB27BC9BB8106DA9EF77B39BE1");

            var chal_secure = NeoHexString.StringToByteArray("2AA02A0D55F506D7CCCAF05D151A8FF1FDC0274566691302DA83BF1DFB5CD4D6");
            var expect_hmac_sign_secure = NeoHexString.StringToByteArray("8F5B21DABF58D59548651B0C284439E52F26E5C4BEEBB1D2DAF4F0F62D67B845");

            var chal = ac_type == "admin" ? chal_admin : chal_secure;

            var sn = ictkpufclass.get_puf_sn_for_byte();

            var read_ac_type = ictkpufclass.readbytekey_in_puf(14, 1);

            var expect_ac_type = Encoding.UTF8.GetString(read_ac_type);
            expect_ac_type = expect_ac_type.Replace("\x00", "");

            var sig = ictkpufclass.sign_hmac_in_puf(12, chal);

            var strSig = NeoHexString.ByteArrayToHexStr(sig);

            return true;
        }

        public string chk_hmac_sign_work(string ac_type, string challenge)
        {
            string retstr = string.Empty;

            var read_ac_type = ictkpufclass.readbytekey_in_puf(14, 1);

            var expect_ac_type = Encoding.UTF8.GetString(read_ac_type);
            expect_ac_type = expect_ac_type.Replace("\x00", "");

            if (expect_ac_type == ac_type)
            {
                var sig = ictkpufclass.sign_hmac_in_puf(12, NeoHexString.StringToByteArray(challenge));

                var strSig = NeoHexString.ByteArrayToHexStr(sig);
                return strSig;
            }

            return string.Empty;
        }

        public string getstringprk_in_puf()
        {
            byte[] prkData = null;
            try
            {
                if (ictkpufclass.ispufconnected() == false)
                    return string.Empty;

                if (!ictkpufclass.set_puf_aes_function(ICTK_ALGORITHM.aes_crypto, ICTK_ALGORITHM.sha_256))
                {
                    return string.Empty;
                }

                byte[] read_data = ictkpufclass.readbytekey_in_puf(15, 1);
                if (read_data != null) { return string.Empty; }

                _KEYCERT_HEADER KeyCertHeader = ByteToStruct<_KEYCERT_HEADER>(read_data);

                prkData = ictkpufclass.readmultikey_in_puf(16, 1, (int)KeyCertHeader.prk_size);
                if (prkData != null)
                {
                    if (verifySHA256chceksumPRK(prkData) == false)
                    {
                        return string.Empty;
                    }
                }
                else { return string.Empty; }
            }
            catch { return null; }
            return (prkData != null) ? NeoHexString.ByteArrayToHexStr(prkData) : string.Empty;
        }

        public byte[] getbytecert_in_puf()
        {
            byte[] read_data = null;
            try
            {
                byte[] prk = new byte[8];

                if (ictkpufclass.ispufconnected() == false) { return null; }

                if (!ictkpufclass.set_puf_aes_function(
                    ICTK_ALGORITHM.aes_crypto, 
                    ICTK_ALGORITHM.sha_256))  { return null; }

                read_data = ictkpufclass.readbytekey_in_puf(15, (int)P2OPTION.OPTION_LOWER_KEY_AREA);
                if (read_data == null) { return null; }

                _KEYCERT_HEADER KeyCertHeader = ByteToStruct<_KEYCERT_HEADER>(read_data);

                byte[] CertData = new byte[(int)KeyCertHeader.cert_size];
                byte[] ConBineData = new byte[((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE) + ((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE)];
                byte[] CertFirstData = ictkpufclass.readmultikey_in_puf(0, (int)P2OPTION.OPTION_LOWER_DATA0_AREA, 
                    ((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE));

                Thread.Sleep(1);
                byte[] CertSecondData = ictkpufclass.readmultikey_in_puf(0, (int)P2OPTION.OPTION_LOWER_DATA1_AREA, 
                    ((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE));
                Thread.Sleep(1);

                Array.Clear(CertData, 0, CertData.Length);
                Array.Clear(ConBineData, 0, ConBineData.Length);
                Array.Copy(CertFirstData, 0, ConBineData, 0, CertFirstData.Length);
                Array.Copy(CertSecondData, 0, ConBineData, CertFirstData.Length, CertSecondData.Length);
                Array.Copy(ConBineData, 0, CertData, 0, (int)KeyCertHeader.cert_size);

                if (verifySHA256chceksumCert(CertData) == false)
                {
                    return null;
                }

                return (CertData != null) ? CertData : null;
            }
            catch { return null; }
        }

        public string getstringcert_in_puf()
        {
            byte[] prk = new byte[8];
            
            try
            {
                if (ictkpufclass.ispufconnected() == false) { return null; }

                if (!ictkpufclass.set_puf_aes_function(ICTK_ALGORITHM.aes_crypto, ICTK_ALGORITHM.sha_256))
                {
                    return string.Empty;
                }

                byte[] read_data = ictkpufclass.readbytekey_in_puf(15, (int)P2OPTION.OPTION_LOWER_KEY_AREA);
                if (read_data == null)
                {
                    
                    for (int i = 0; i < 3; i++)
                    {
                        ictkpufclass.puf_wakeup();
                        Thread.Sleep(1);

                        read_data = ictkpufclass.readbytekey_in_puf(15, (int)P2OPTION.OPTION_LOWER_KEY_AREA);
                        if (read_data != null)
                        {
                            break;
                        }
                    }

                    if (read_data == null) { return  string.Empty; }
                }
                
                _KEYCERT_HEADER KeyCertHeader = ByteToStruct<_KEYCERT_HEADER>(read_data);
                byte[] CertData = new byte[((int)KeyCertHeader.cert_size)];
                byte[] ConBineData = new byte[(((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE) + 
                    ((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE))];

                byte[] CertFirstData = ictkpufclass.readmultikey_in_puf(0, 
                    (int)P2OPTION.OPTION_LOWER_DATA0_AREA, 
                    ((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE));

                if (CertFirstData == null)
                {
                    for (int i = 0; i < 3; i++)
                    {
                        ictkpufclass.puf_wakeup();
                        Thread.Sleep(1);

                        CertFirstData = ictkpufclass.readmultikey_in_puf(0,
                            (int)P2OPTION.OPTION_LOWER_DATA0_AREA,
                            ((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE));

                        if (CertFirstData != null)
                            break;
                    }

                    if (CertFirstData == null) {return string.Empty; }
                }

                byte[] CertSecondData = ictkpufclass.readmultikey_in_puf (0, 
                    (int)P2OPTION.OPTION_LOWER_DATA1_AREA, 
                    ((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE));

                if (CertSecondData == null)
                {
                    for (int i = 0; i < 3; i++)
                    {
                        ictkpufclass.puf_wakeup();
                        Thread.Sleep(1);

                        CertSecondData = ictkpufclass.readmultikey_in_puf(0,
                            (int)P2OPTION.OPTION_LOWER_DATA1_AREA,
                            ((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE));

                    }
                    if (CertSecondData == null) { return string.Empty; }
                }

                if (CertFirstData == null || CertSecondData == null)   { return String.Empty;  }

                Array.Clear(CertData,       0, CertData.Length);
                Array.Clear(ConBineData,    0, ConBineData.Length);
                Array.Copy (CertFirstData,  0, ConBineData, 0, CertFirstData.Length);
                Array.Copy (CertSecondData, 0, ConBineData, CertFirstData.Length, CertSecondData.Length);
                Array.Copy (ConBineData,    0, CertData, 0, (int)KeyCertHeader.cert_size);

                if (verifySHA256chceksumCert(CertData) == false) { return string.Empty; }

                return  (CertData != null) ? NeoHexString.ByteArrayToHexStr(CertData) : string.Empty;
            }
            catch { return null; }
        }

        public string getstring_challenge_in_puf()
        {
            return ictkpufclass.get_challenge_in_puf();
        }

        public bool proceed_fingerprintverif()
        {
            try
            {
                if (ictkpufclass.ispufconnected() == false) { return false; }

                return (ictkpufclass.verif_fingerprint());
            }
            catch { return false; }
        }

        public void check_hmac_sign(string ac_type)
        {
            if (ictkpufclass.ispufconnected() == true)
            {
                if (!ictkpufclass.set_puf_aes_function(ICTK_ALGORITHM.aes_crypto, ICTK_ALGORITHM.sha_256))
                {
                    return;
                }

                ictkpufclass.puf_wakeup();

                var sn = ictkpufclass.get_puf_sn_for_byte();
                //ictkpufclass.sign_hmac_in_puf(12, )

            }
        }


        void IDisposable.Dispose()
        {
            throw new NotImplementedException();
        }

    }
}
