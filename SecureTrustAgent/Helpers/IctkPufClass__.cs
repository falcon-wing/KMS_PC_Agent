#define SUPPORT_FINGERPRINT
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
using static SecureTrustAgent.Helpers.ictk_puf_warpper;
//using SecIotAgent.DEFINE;
//using SecIotAgent.Common;


//delegate void DELEGATE_VERIFY(int32_t ret);

namespace SecIotAgent.PUF
{

    public struct OBJECT_TYPE_A
    {


    }

    

    public class ICTK_ALGORITHM : IDisposable
    {

        Logs common = new Logs();

        

        public static Byte[] aes_crypto(bool encdec, Byte[] key, Byte[] msg, Byte[] iv)
        {

#pragma warning disable SYSLIB0022 // 형식 또는 멤버는 사용되지 않습니다.
            RijndaelManaged aes = new RijndaelManaged();
#pragma warning restore SYSLIB0022 // 형식 또는 멤버는 사용되지 않습니다.
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

        public static Byte[] sha_256(Byte[] msg)
        {
            try
            {
                SHA256 mySHA256 = SHA256.Create();

                byte[] hashValue = mySHA256.ComputeHash(msg);
                return hashValue;
            }catch(Exception e)
            {
                Debug.WriteLine(e.Message);
                return null;
            }
        }

        void IDisposable.Dispose()
        {
            throw new NotImplementedException();
        }
    }

    public class PUF_API_CLASS : IDisposable
    {
        /// <summary>
        /// </summary>
        public static PqcG3API obj;
        public NeoRandom neo = new NeoRandom();
        Logs common = new Logs();
        private readonly object balanceLock = new object();
        /// <summary>
        /// 
        /// </summary>
        public PqcG3API Obj
        {
#pragma warning disable CS8603 // 가능한 null 참조 반환입니다.
            get => obj;
#pragma warning restore CS8603 // 가능한 null 참조 반환입니다.
            set { obj = value; }    
        }

       

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public bool chip_init()
        {
            if (obj is null)
                return false;
#if DEBUG_MSG
            Debug.WriteLine("[ICTK_PUF_CLASS::chip_init] CALL INIT..........");
#endif
            obj.init();

            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public bool chip_wakeup()
        {
            if (obj is null)
            {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER chip_wakeup:: obj is null", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                return false;
            }

            obj.wake_up();

            return true;
        }

        public void chip_end()
        {
            if (obj is null)
            {
                return;
            }

            bool bConnect = false;

            try
            {
                obj.end();
            }
            catch (Exception e)
            {
#if DEBUG_MSG
                string errmsg = "FAIL TO DEVICE OPER chip_is_conncted::EXCEPT - " + e.Message;
                common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                Debug.WriteLine(e.Message);
            }

            return ;
        }

        //void DELEGATE_VERIFY(int32_t ret);
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public bool chip_is_conncted()
        {
#if DEBUG_MSG
            common.Log_info("FAIL TO DEVICE OPER chip_is_conncted start", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif

            if (obj is null)
            {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER chip_is_conncted::obj is null", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                return false;
            }

            bool bConnect = false;

            try
            {
                bConnect = obj.IsConnected();
            }catch (Exception e)
            {
#if DEBUG_MSG
                string errmsg = "FAIL TO DEVICE OPER chip_is_conncted::EXCEPT - " + e.Message;
                common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                Debug.WriteLine(e.Message);
            }

            return bConnect;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="nsize"></param>
        /// <returns></returns>
        public byte[] chip_get_challenage_for_byte(int nsize)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                    return null;

                byte[] challenge = null;

                try
                {
                    challenge = obj.get_challenge(nsize);
                }
                catch (Exception e)
                {
                    //  string errmsg = "fail to get information form puf chip... [" + e.Message + "]";
                    //  common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.WEBSOCKET);

                    Debug.WriteLine(e.Message);
                }

                return challenge;
            }
        }

        public bool chip_reset_puf(byte[] challenge, byte[] sign)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER chip_get_challenage_for_string::obj is null", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                    return false;
                }


                try
                {
                    string ac_key = "52d508da8991f503a08bdce69f0cf72ca1f40abb846a24ded750517dbb80e79b93b72db9e2799d919f44468e53dc194361f8611935c0b91b516da395dbf5c67b";
                    int ret = obj.reset_puf(2, challenge, sign, NeoHexString.HexStringToByteArray(ac_key));

                    if (ret == 0)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }

                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                    // string errmsg = "fail to get information form puf chip... [get challenge][" + e.Message + "]";
                    // common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.WEBSOCKET);
                }

                return false;
            }
        }
/*
        public bool chip_sign_verify(byte[] challenge, byte[] sign)
        {
            if (obj is null)
            {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER chip_get_challenage_for_string::obj is null", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                return false;
            }


            try
            {
                int ret = obj.sign_verify(2, challenge, sign );

                if (ret == 0)
                {
                    return true;
                }
                else
                {
                    return false;
                }

            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
                // string errmsg = "fail to get information form puf chip... [get challenge][" + e.Message + "]";
                // common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.WEBSOCKET);
            }

            return false;
        }
*/
        /// <summary>
        /// 
        /// </summary>
        /// <param name="nsize"></param>
        /// <returns></returns>
        public string chip_get_challenage_for_string(int nsize)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER chip_get_challenage_for_string::obj is null", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                    return String.Empty;
                }


                try
                {
                    var buffer = obj.get_challenge(nsize);

                    if (buffer != null)
                    {
                        return NeoHexString.ByteArrayToHexStr(buffer);
                    }

                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                    // string errmsg = "fail to get information form puf chip... [get challenge][" + e.Message + "]";
                    // common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.WEBSOCKET);
                }

                return String.Empty;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public byte[]? chip_get_serialnumber_for_byte()
        {
            //lock (balanceLock)
            {
                if (obj is null)
                {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER chip_get_serialnumber_for_byte::obj is null", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                    return null;
                }

                byte[] SN = null;
                try
                {
                    SN = obj.get_sn();
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                    //  string errmsg = "fail to get information form puf chip... [get serialnumber][" + e.Message + "]";
                    // common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.WEBSOCKET);
                }

                return SN;
            }
        }

        public void chip_g3p_reset()
        {
            if (obj is null)
            {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER chip_get_serialnumber_for_string::obj is null", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                return;
            }

            try
            {
                obj.g3_reset();

            }
            catch (Exception e)
            {

            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public string chip_get_serialnumber_for_string()
        {
            //lock (balanceLock)
            {
                if (obj is null)
                {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER chip_get_serialnumber_for_string::obj is null", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                    return String.Empty;
                }

                try
                {
                    var buffer = obj.get_sn();
                    if (buffer != null)
                    {
#if DEBUG_MSG
                    common.Log_info("FAIL TO DEVICE OPER chip_get_serialnumber_for_string::obj.get_sn() is not null !!!!", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                        return NeoHexString.ByteArrayToHexStr(buffer);
                    }
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                    // string errmsg = "fail to get information form puf chip... [get serialnumber::str][" + e.Message + "]";
                    // common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.WEBSOCKET);

                }

                return String.Empty;
            }
        }

        public byte[] fingerprint_G3_verify()
        {
            //lock (balanceLock)
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
        }

        public int fingerprint_RemoveTemplate()
        {
            //lock (balanceLock)
            {
                int ret = 0;
                if (obj is null)
                {
                    return 0;
                }
                try
                {
                    ret = obj.FingerPrint_G3_RemoveTemplate();
                    return ret;
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
                return 0;
            }
        }

        public int fingerprint_fp_MACverify()
        {
            //lock (balanceLock)
            {
                int ret = 0;
                if (obj is null)
                {
                    return 0;
                }
                try
                {
                    ValueType buflen = 0;
                    byte[] buffer = new byte[4096];
                    ret = obj.FingerPrint_G3_MacVerify(buffer, ref buflen);
                    return ret;
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
                return 0;
            }
        }


        public int fingerprint_fp_verify()
        {
            //lock (balanceLock)
            {
                int ret = 0;
                if (obj is null)
                {
                    return 0;
                }
                try
                {
                    ValueType buflen = 0;
                    byte[] buffer = new byte[4096];
                    ret = obj.FingerPrint_FP_Verify(buffer, ref buflen);
                    return ret;
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
                return 0;
            }
        }



        public int fingerprint_GetPermission()
        {
            //lock (balanceLock)
            {
                int ret = 0;
                if (obj is null)
                {
                    return 0;
                }
                try
                {
                    ValueType buflen = 0;
                    byte[] buffer = new byte[4096];

                    ret = obj.FingerPrint_G3_GetPermission(buffer, ref buflen);

                    return ret;
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }

                return 0;
            }
        }

        public int fingerprint_enroll()
        {
            //lock (balanceLock)
            {
                if (obj is null)
                {
                    return 0;
                }
                try
                {
                    return obj.FingerPrint_G3_Enroll();
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }
                return 0;
            }
        }


        public int fingerprint_enrolled()
        {
            //lock (balanceLock)
            {
                if (obj is null)
                {
                    return 0;
                }
                try
                {
                    return obj.FingerPrint_G3_isEnrolled();
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }

                return 0;
            }
        }

        //public int Linking_VirifyEvent()

        public bool pqc_kem_enc(byte[] enc_key, byte[] share_key, byte[] pk)
        {
            if (obj is null)
            {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER pqc_kem_enc::obj is null", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                return false;
            }

            try
            {
                //byte[] enc_key = new byte[2 * 1088];
                obj._pqc_wrapper_kem_enc(enc_key, share_key, pk);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
                string errmsg = "fail to get information form puf chip... [pqc_kem_enc][" + e.Message + "]";
                common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
            }

            return true;
        }

        public bool pqc_kem_dec(byte[] share_key, byte[] enc_key, byte[] sk)
        {
            if (obj is null)
                return false;

            try
            {
                //byte[] enc_key = new byte[2 * 1088];
                obj._pqc_wrapper_kem_dec(share_key, enc_key, sk);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
                string errmsg = "fail to get information form puf chip... [pqc_kem_dec][" + e.Message + "]";
                common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
            }

            return true;
        }

        public byte[] pqc_wrapper_sign_signature(
            
            byte[] _msg,int msgsize, byte[] _sk)
        {
            byte[] out_data = new byte[3094];

            if (obj is null)
                return null;

            int nSize = 0;
            //byte[] out_data = null;

            try
            {
                byte[] pk = new byte[1024];
                out_data = obj._pqc_wrapper_sign_signature(_msg, msgsize, _sk);
            }catch(Exception e)
            {
                Debug.WriteLine(e.Message);
                string errmsg = "fail to get information form puf chip... [pqc_sign_signature][" + e.Message + "]";
                common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
            }

            return out_data;
        }

        public int pqc_wrapper_sig_verify(byte[] _sig, int _siglen, byte[] _msg, int _msglen, byte[] _pk)
        {
            if (obj is null)
                return 0;

            int Ret = 0;
            //byte[] out_data = null;

            try
            {
                byte[] pk = new byte[1024];
                Ret = obj._pqc_wrapper_sign_verify(_sig, (uint)_siglen, _msg, (uint)_msglen, _pk);//_pqc_wrapper_sign_signature(_msg, msgsize, _sk);
            }
            catch (Exception e)
            {
                Debug.WriteLine(e.Message);
                string errmsg = "fail to get information form puf chip... [pqc_sign_verify][" + e.Message + "]";
                common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
            }

            return Ret;
        }


        public bool chip_verify_pw_by_byte_for_fa500()
        {
            if (obj is null)
                return false;

            try
            {
                ValueType buflen = 0;
                byte[] buffer = new byte[4096];
                int ret = obj.FingerPrint_G3_GetPermission(buffer, ref buflen);
                if (ret != 0)
                {
                    return false;
                }

                System.Array.Clear(buffer, 0, buffer.Length);

                ret = obj.FingerPrint_G3_Verify(buffer, ref buflen);

            }catch(Exception e)
            {
                Debug.WriteLine(e.Message);
            }
            return true;
        }
            /// <summary>
            /// 
            /// </summary>
            /// <param name="keyindex"></param>
            /// <param name="pw"></param>
            /// <returns></returns>
        public bool chip_verify_pw_by_byte(int keyindex, byte[] pw)
        {
            if (obj is null)
                return false;

            try
            {
                if (keyindex < 0 || pw is null)
                {
                    return false;
                }

                obj.verify_pw(keyindex, pw);
            }
            catch(Exception e)
            {
                Debug.WriteLine(e.Message);
                string errmsg = "fail to get information form puf chip... [chip_verify_pw::byte][" + e.Message + "]";
                common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
            }
            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyindex"></param>
        /// <param name="pw"></param>
        /// <returns></returns>
        public bool chip_verify_pw_by_string(int keyindex, string pw)
        {
            if (obj is null)
                return false;

            try
            {
                if (keyindex < 0 || pw is null)
                {
                    return false;
                }

                obj.verify_pw(keyindex, NeoHexString.HexStringToByteArray(pw));
            }catch (Exception e)
            {
                Debug.WriteLine(e.Message);
                string errmsg = "fail to get information form puf chip... [chip_verify_pw::str][" + e.Message + "]";
                common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
            }

            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="new_pw"></param>
        /// <returns></returns>
        public bool chip_write_password(string new_pw)
        {
            if (obj is null || new_pw is null)
                return false;

            try
            {
                obj.write_pw(NeoHexString.HexStringToByteArray(new_pw));
            }catch(Exception e)
            {
                Debug.WriteLine(e.Message);
            }

            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyindex"></param>
        /// <param name="keyarea"></param>
        /// <param name="new_msg"></param>
        /// <returns></returns>
        public bool chip_write_key(int keyindex, int keyarea, string new_msg)
        {
            if (obj is null || new_msg is null)
                return false;

            try
            {
                obj.write_key(keyindex, keyarea, NeoHexString.HexStringToByteArray(new_msg));
            }catch(Exception e)
            {
                Debug.WriteLine(e.Message);
            }

            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyindex"></param>
        /// <param name="keyarea"></param>
        /// <returns></returns>
        public byte[] ?chip_read_key_for_byte(int keyindex, int keyarea)
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
            catch(Exception e)
            {
                Debug.WriteLine(e.Message);
            }

            return null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyindex"></param>
        /// <param name="keyarea"></param>
        /// <returns></returns>
        public string chip_read_key_for_string(int keyindex, int keyarea)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                    return String.Empty;


                return NeoHexString.ByteArrayToHexStr(obj.read_key(keyindex, keyarea));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyindex"></param>
        /// <param name="keyarea"></param>
        /// <param name="new_msg"></param>
        /// <returns></returns>
        public bool chip_write_multi_key_by_byte(int keyindex, int keyarea, byte[] new_msg)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                    return false;

                try
                {
                    obj.write_multi_key(keyindex, keyarea, new_msg);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }

                return true;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyindex"></param>
        /// <param name="keyarea"></param>
        /// <param name="new_msg"></param>
        /// <returns></returns>
        public bool chip_write_multi_key_by_string(int keyindex, int keyarea, string new_msg)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                    return false;

                try
                {
                    obj.write_multi_key(keyindex, keyarea, NeoHexString.HexStringToByteArray(new_msg));
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }

                return true;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyindex"></param>
        /// <param name="keyarea"></param>
        /// <param name="readsize"></param>
        /// <returns></returns>
        public byte[] ?chip_read_multi_key(int keyindex, int keyarea, int readsize)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                    return null;

                byte[] read_multi_key = null;

                try
                {
                    read_multi_key = obj.read_multi_key(keyindex, keyarea, readsize);

                    if (read_multi_key == null)
                    {
                        for (int i = 0; i < 3; i++)
                        {
                            read_multi_key = obj.read_multi_key(keyindex, keyarea, readsize);
                            if (read_multi_key != null)
                            {
                                break;
                            }
                        }
                    }

                    if (read_multi_key == null)
                    {
                        return null;
                    }

                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }

                return read_multi_key;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyindex"></param>
        /// <param name="keyarea"></param>
        /// <param name="readsize"></param>
        /// <returns></returns>
        public string chip_read_multi_key_for_string(int keyindex, int keyarea, int readsize)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                    return String.Empty;

                byte[] multi_key = null;

                try
                {
                    multi_key = obj.read_multi_key(keyindex, keyarea, readsize);
                    if (multi_key == null)
                    {
                        for (int i = 0; i < 3; i++)
                        {
                            multi_key = obj.read_multi_key(keyindex, keyarea, readsize);
                            if (multi_key != null)
                            {
                                break;
                            }
                        }
                    }

                    if (multi_key != null)
                    {
                        return String.Empty;
                    }
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }

                return NeoHexString.ByteArrayToString(multi_key);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keytype"></param>
        /// <param name="new_msg"></param>
        /// <returns></returns>
        public bool chip_write_with_header_by_byte(pqcclrwrap.KEYTYPE keytype, byte[] new_msg)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                    return false;

                try
                {

                    obj.write_with_header(keytype, new_msg);
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                }

                return true;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keytype"></param>
        /// <param name="new_msg"></param>
        /// <returns></returns>
        public bool chip_write_with_header_by_string(pqcclrwrap.KEYTYPE keytype, byte[] new_msg)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                    return false;

                obj.write_with_header(keytype, new_msg);

                return true;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keytype"></param>
        /// <returns></returns>
        public byte[] ?chip_read_with_header_for_byte(pqcclrwrap.KEYTYPE keytype)
        {
            if (obj is null)
                return null;

            return obj.read_with_header(keytype);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keytype"></param>
        /// <returns></returns>
        public string chip_read_with_header_for_string(pqcclrwrap.KEYTYPE keytype)
        {
            if (obj is null)
                return String.Empty;

            return NeoHexString.ByteArrayToString(obj.read_with_header(keytype));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="aes_crypt"></param>
        /// <param name="sha_256"></param>
        /// <returns></returns>
        public bool set_aes_function(AES_CRYPT aes_crypt, SHA_256 sha_256)
        {
            //lock (balanceLock)
            {
                if (obj is null)
                    return false;

                obj.set_aes_fn(aes_crypt, sha_256);

                return true;
            }
        }

        void IDisposable.Dispose()
        {
            throw new NotImplementedException();
        }
    }

    internal class ICTK_PUF_Class 
    {
#region Field

        public string system_constant = "632854F31C456408B6A3F9B20024EADA";//"4C4755504C55532D5051432D44454D4F2D53595354454D2D434F4E5354414E54";

        /// <summary>
        /// WM_DEVICECHANGE
        /// </summary>
        public const int WM_DEVICECHANGE = 0x0219;

        /// <summary>
        /// DBT_DEVTYP_DEVICEINTERFACE
        /// </summary>
        public const int DBT_DEVTYP_DEVICEINTERFACE = 0x05;

        /// <summary>
        /// DEVICE_NOTIFY_WINDOW_HANDLE
        /// </summary>
        public const int DEVICE_NOTIFY_WINDOW_HANDLE = 0x00000000;

#endregion

        PUF_API_CLASS ictk_puf_api = new PUF_API_CLASS();
        ICTK_ALGORITHM ictk_algorithm = new ICTK_ALGORITHM();
        Logs common = new Logs();

        public bool _chip_verify_pw_by_byte(int keyindex, byte[] pw)
        {
            return ictk_puf_api.chip_verify_pw_by_byte(keyindex, pw);
        }

        public bool set_puf_aes_function(AES_CRYPT aes_crypt, SHA_256 sha_256)
        {
            ictk_puf_api.set_aes_function(aes_crypt, sha_256);
            return true;
        }

        public static void Delegate_Work(int workType, int data)
        {


        }

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

        public bool PqcG3API_FA500InitObject_test()
        {
            var pqcApi = new PqcG3API();
            if (pqcApi != null)
            {

                pqcApi.FA500_init();
                ictk_puf_api.Obj = pqcApi;
            }
            else
            {
                return false;
            }

            ValueType buflen = 0;
            byte[] G3verifybuffer = new byte[16];
            byte[] verifybuffer = new byte[4096];
            byte[] buffer = new byte[4096];
            byte[] tmp = new byte[20];
            ValueType verifybuflen = 0, G3verifybuflen = 0;

            pqcApi._FA500_WBM_InitVerifyDelegate(Delegate_Work);
            int ret = pqcApi.FingerPrint_G3_GetPermission(buffer, ref buflen);
            ret = pqcApi.FingerPrint_FP_Verify(verifybuffer, ref verifybuflen);
            pqcApi.FingerPrint_G3_Verify(tmp, ref G3verifybuflen);
            Array.Copy(tmp, 1, G3verifybuffer, 0, 16);
            pqcApi.FingerPrint_G3_SetSessionKey(G3verifybuffer);
            pqcApi.set_aes_fn(aes_crypto, sha_256);

            pqcApi.wake_up();
            var sn = pqcApi.get_sn();

            var read_data = pqcApi.read_key(15, 1);


            return true;

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
                    //if(!ictkpuf.set_puf_aes_function(ICTK_ALGORITHM.aes_crypto, ICTK_ALGORITHM.sha_256))
                    pqcApi.set_aes_fn(ICTK_ALGORITHM.aes_crypto, ICTK_ALGORITHM.sha_256);
                }
                else
                {
                    return false;
                }

            }
            catch(Exception e)
            {

                Debug.WriteLine(e.Message);
            }
            return true;
        }

        public bool PqcG3API_InitObject(string system_constant)
        {
            byte[] data = NeoHexString.StringToByteArray(system_constant);
            try
            {
#if DEBUG_MSG
                string msg = "FAIL TO DEVICE OPER PqcG3API_InitObject::system_constant -" + system_constant;
                common.Log_info(msg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                var pgpg3api = new PqcG3API();
                if (pgpg3api != null)
                {
#if DEBUG_MSG
                    common.Log_info("var pgpg3api = new PqcG3API(data) is success....", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                    pgpg3api.FA500_init();
                    ictk_puf_api.Obj = pgpg3api;
                }
                else
                {
#if DEBUG_MSG
                    common.Log_info("var pgpg3api = new PqcG3API(data) is FAIL!!....", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                    return false;
                }
            }catch (Exception e)
            {
                string msg = "PqcG3API_InitObject is FAIL!!.... - EXcept :" + e.Message;
                common.Log_info(msg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
                Debug.WriteLine(e.Message);
            }

            return true;
        }

        public bool is_puf_connect()
        {
            /*if (ictk_puf_api.chip_init() == false)
            {
                //DO LOG

                return false;
            }
            */

            return ictk_puf_api.chip_is_conncted() ? true : false;
        }

        public void puf_end()
        {
            ictk_puf_api.chip_end();
        }

        public string get_puf_challenge()
        {
            return ictk_puf_api.chip_get_challenage_for_string(32);
        }

        public string get_puf_sn()
        {
            // ictk_puf_api.fingerprint_GetPermission();

            

            if (ictk_puf_api.chip_wakeup() != true)
            {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER get_puf_sn::ictk_puf_api.chip_wakeup", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                return String.Empty;
            }

            if (ictk_puf_api.chip_is_conncted() != true)
            {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER get_puf_sn::ictk_puf_api.chip_is_conncted", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                return String.Empty;
            }

            //return ictk_puf_api.chip_get_serialnumber_for_string();

            if (ictk_puf_api.chip_wakeup() != true)
            {
#if DEBUG_MSG
                common.Log_info("FAIL TO DEVICE OPER get_puf_sn::ictk_puf_api.chip_wakeup", (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.DEVICE);
#endif
                return String.Empty;
            }

            return ictk_puf_api.chip_get_serialnumber_for_string();
        }

        public byte[]? get_puf_sn_byte()
        {
            ictk_puf_api.chip_wakeup();
            if (ictk_puf_api.chip_is_conncted() != true)
            {
                return null;
            }

            if (ictk_puf_api.chip_wakeup() != true)
            {
                return null;
            }

            return ictk_puf_api.chip_get_serialnumber_for_byte();
        }

        public bool puf_wakeup()
        {
            //ictk_puf_api.chip_init();
            if (ictk_puf_api.chip_wakeup() != true)
            {
                return false;
            }
           

            return true;
        }

        public byte[]? _chip_read_key_for_byte(int keyindex, int keyarea)
        {
            return ictk_puf_api.chip_read_key_for_byte(keyindex, keyarea);
        }
        
        public byte[] _chip_read_multi_key(int keyindex, int keyarea, int readsize)
        {
            ictk_puf_api.chip_wakeup();
            return ictk_puf_api.chip_read_multi_key(keyindex, keyarea, readsize);
        }
        
        public byte[] pqc_wrapper_sign_signature(
            byte[] _m, int _mlen,
            byte[] _sk)
        {
            
            return ictk_puf_api.pqc_wrapper_sign_signature(_m, _mlen, _sk);
        }

        public int pqc_wrapper_sign_verify(byte[] _sig, int _siglen, byte[] _msg, int _msglen, byte[] _pk)
        {
            return ictk_puf_api.pqc_wrapper_sig_verify(_sig, _siglen, _msg, _msglen, _pk);
        }

        /// <summary>
        /// * Name:        crypto_kem_enc
        /// 
        /// * Description: Generates cipher text and shared
        ///                secret for given public key
        ///                
        /// Arguments:   
        ///               - unsigned char *ct: pointer to output cipher text
        ///                 (an already allocated array of CRYPTO_CIPHERTEXTBYTES bytes)
        ///               - unsigned char* ss: pointer to output shared secret
        ///                 (an already allocated array of CRYPTO_BYTES bytes)
        ///               - const unsigned char* pk: pointer to input public key
        ///                 (an already allocated array of CRYPTO_PUBLICKEYBYTES bytes)
        ///                 
        /// Returns 0 (success)
        /// 
        /// </summary>
        /// <param name="enc_key"></param>
        /// <param name="share_key"></param>
        /// <param name="pk"></param>
        /// <returns></returns>
        public bool _pqc_kem_enc(byte[] cipher_text, byte[] share_key, byte[] public_key)
        {
            return ictk_puf_api.pqc_kem_enc(cipher_text, share_key, public_key);
        }

        public bool _pqc_kem_dec(byte[] share_key, byte[] enc_key, byte[] sk)
        {
            
            return ictk_puf_api.pqc_kem_dec(share_key, enc_key, sk);
        }

        /// <summary>
        /// ENC_KEY,SHARE_KEY = PQC-KEM-ENC(KE_PK)
        /// </summary>
        /// <param name="enc_key"></param>
        /// <param name="share_key"></param>
        /// <param name="kePk : KEM 인증을 위한 인증서버의 public key(key type : kyber) 정보"></param>
        /// <returns></returns>
        public bool _pqc_kem_dec_generator(ref byte[] cipher_text, ref byte[] share_key , string kePk)
        {
            byte[] share_key_bak = new byte[2048];
            bool Ret = _pqc_kem_enc(cipher_text, share_key_bak, NeoHexString.StringToByteArray(kePk));
            Array.Copy(share_key_bak, share_key, 32);

            if (Ret == false)
            { 
                return true; 
            }
            
            return false;
        }
        
    }

    public class ICTKPupWarpClass : IDisposable
    {
        ICTK_PUF_Class ictkpuf = new ICTK_PUF_Class();
        ICTK_ALGORITHM argorithm = new ICTK_ALGORITHM();

        int PUF_KEY_INDEX_HEADER = 15;
        int PUF_KEY_INDEX_PRK = 16;
        int PUF_SECTER_SIZE = 32;
        int PUF_SECTER_PRK_SHA2_SIGNUMHASH = 118;
        int PUF_SECTER_CERT_SHA2_SIGNUMHASH = 119;
        public NeoRandom neo = new NeoRandom();

        //STR_SHA2_PRK_SIGNUMHASH

        /// <summary>
        ///Lower byte  
        ///    00 – setup area
        ///    01 – key area
        ///    02 – data area Data0
        ///    03 – data area Data1
        /// </summary>

        public enum P2OPTION
        {
            OPTION_LOWER_SETUP_AREA = 0,
            OPTION_LOWER_KEY_AREA   = 1,
            OPTION_LOWER_DATA0_AREA = 2,
            OPTION_LOWER_DATA1_AREA = 3,
        }

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
            catch(Exception e)
            {
                Debug.WriteLine("failt to ByteToStruct...");
            }

            return obj;
        }

       /* public bool Init()
        {
            return true;
        }
       */

        public string Get_puf_Challenge_String()
        {
            return ictkpuf.get_puf_challenge();
        }

        public string Get_puf_SerialNumber()
        {
            return ictkpuf.get_puf_sn();
        }
        ///
        ///Verify SHA-256 checksum
        public bool VerifySHA256ChceksumPRK(byte[] _PrkData)
        {
            byte[] PrkSHA2 =ICTK_ALGORITHM.sha_256(_PrkData);
            string sha2 = NeoHexString.ByteArrayToHexStr(PrkSHA2);

            byte[] PRK_SHA2_HASH = ictkpuf._chip_read_key_for_byte(PUF_SECTER_PRK_SHA2_SIGNUMHASH, 1);//4번키의 값을 읽는다. AC 1을 얻어야 한다. 

            //if (string.Compare(NeoHexString.ByteArrayToHexStr(PrkSHA2), Properties.Resources.STR_SHA2_PRK_SIGNUMHASH, true) == 0)
            if (string.Compare(NeoHexString.ByteArrayToHexStr(PrkSHA2), NeoHexString.ByteArrayToHexStr(PRK_SHA2_HASH), true) == 0)
            {
                return true;
            }
            return false;
        }

        public bool VerifySHA256ChceksumCert(byte[] _CertData)
        {
            try
            {
                byte[] CertSHA2 = ICTK_ALGORITHM.sha_256(_CertData);
                string sha2 = NeoHexString.ByteArrayToHexStr(CertSHA2);
                byte[] CERT_SHA2_HASH = ictkpuf._chip_read_key_for_byte(PUF_SECTER_CERT_SHA2_SIGNUMHASH, 1);//4번키의 값을 읽는다. AC 1을 얻어야 한다. 

                if (string.Compare(NeoHexString.ByteArrayToHexStr(CertSHA2), NeoHexString.ByteArrayToHexStr(CERT_SHA2_HASH), true) == 0)
                {
                    return true;
                }
            }catch(Exception e)
            {
                Debug.WriteLine(e.ToString());
                return false;
            }

            return false;
        }

        public byte[] ?GetPUF_Prk()
        {
            if (ictkpuf.is_puf_connect() != true)
            {
                return null;
            }
            else
            {
                if(!ictkpuf.set_puf_aes_function(ICTK_ALGORITHM.aes_crypto , ICTK_ALGORITHM.sha_256))
                {
                    return null;
                }
#if SUPPORT_FINGERPRINT
#else //SUPPORT_FINGERPRINT
                if (!ictkpuf._chip_verify_pw_by_byte(0, sn))//AC 0을 얻는다.
                {
                    return null;
                }
#endif //SUPPORT_FINGERPRINT
               // Thread.Sleep(1000);

                ictkpuf.puf_wakeup();

                byte[]? read_data = ictkpuf._chip_read_key_for_byte(15, 1);
                if (read_data == null)
                {
                    return null;
                }
                _KEYCERT_HEADER KeyCertHeader = ByteToStruct<_KEYCERT_HEADER>(read_data);
                //Thread.Sleep(1000);
                Console.WriteLine("PRK-COLLECT-READ_HEADERAFTER!! >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");

                Console.WriteLine("PRK-COLLECT-START!! >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
                byte[] PrkData = ictkpuf._chip_read_multi_key(PUF_KEY_INDEX_PRK, (int)P2OPTION.OPTION_LOWER_KEY_AREA, (int)KeyCertHeader.prk_size);
                if (VerifySHA256ChceksumPRK(PrkData) == false)
                {
                    return null;
                }
                Console.WriteLine("PRK-COLLECT-END!! >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");



                return PrkData;
            }

#pragma warning disable CS0162 // 접근할 수 없는 코드가 있습니다.
            return null;
#pragma warning restore CS0162 // 접근할 수 없는 코드가 있습니다.
        }

        

        public string? GetPUF_Prk_by_string()
        {
#if DEBUG_MSG
            Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] Start===================================");
#endif
            byte[] prk = new byte[8];
            ictkpuf.puf_wakeup();
            if (ictkpuf.is_puf_connect() != true)
            {
                return String.Empty;
            }
            else
            {
#if DEBUG_MSG
                Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] is_puf_connect success===================================");
#endif
                var sn = ictkpuf.get_puf_sn_byte();
#if DEBUG_MSG
                Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] get_puf_sn_byte success");
#endif
                if (!ictkpuf.set_puf_aes_function(ICTK_ALGORITHM.aes_crypto, ICTK_ALGORITHM.sha_256))
                {
                    Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] set_puf_aes_function fail");
                    return String.Empty;
                }

                Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] set_puf_aes_function success");
#if SUPPORT_FINGERPRINT
#else //SUPPORT_FINGERPRINT
                if (!ictkpuf._chip_verify_pw_by_byte(0, sn))//AC 0을 얻는다.
                {
                    return String.Empty;
                }

                Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] _chip_verify_pw_by_byte success");

                Thread.Sleep(0);
#endif
                //byte[] read_data = ictkpuf._chip_read_key_for_byte(PUF_KEY_INDEX_HEADER, 1);//4번키의 값을 읽는다. AC 1을 얻어야 한다. 
                byte[] read_data = ictkpuf._chip_read_key_for_byte(15, 1);//4번키의 값을 읽는다. AC 1을 얻어야 한다. 

                Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] _chip_read_key_for_byte success");

                if (read_data == null)
                {
                    return String.Empty;
                }

                _KEYCERT_HEADER KeyCertHeader = ByteToStruct<_KEYCERT_HEADER>(read_data);
                Thread.Sleep(0);

                //byte[] PrkData = ictkpuf._chip_read_multi_key(PUF_KEY_INDEX_PRK, (int)P2OPTION.OPTION_LOWER_KEY_AREA, (int)KeyCertHeader.prk_size);
                Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] _chip_read_multi_key start");
                byte[] PrkData = ictkpuf._chip_read_multi_key(16, 1, (int)KeyCertHeader.prk_size);
                Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] _chip_read_multi_key end");

                if (PrkData != null)
                {
                    if (VerifySHA256ChceksumPRK(PrkData) == false)
                    {
                        Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] VerifySHA256ChceksumPRK fail");
                        return string.Empty;
                    }
                }
                else {

                    Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] VerifySHA256ChceksumPRK fail V2");
                    return string.Empty;
                }

                Debug.WriteLine("[PUF_API_CLASS::GetPUF_Prk_by_string] VerifySHA256ChceksumPRK success");

                return String.Format("{0}", NeoHexString.ByteArrayToHexStr(PrkData)); ;
            }

#pragma warning disable CS0162 // 접근할 수 없는 코드가 있습니다.
            return String.Empty;
#pragma warning restore CS0162 // 접근할 수 없는 코드가 있습니다.
        }

        public string _GetRandText_string(int length)
        {
            return NeoHexString.ByteArrayToHexStr(neo.GetRandText(length)) ;
        }

        public byte[]? GetPUF_Cert()
        {
            byte[] prk = new byte[8];

            // public bool puf_wakeup()
           // var sn = ictkpuf.get_puf_sn_byte();

            if (ictkpuf.is_puf_connect() != true)
            {
                return prk;
            }
            else
            {
                if(!ictkpuf.set_puf_aes_function(ICTK_ALGORITHM.aes_crypto, ICTK_ALGORITHM.sha_256))
                {
                    return null;
                }
#if SUPPORT_FINGERPRINT
#else //SUPPORT_FINGERPRINT
                if (!ictkpuf._chip_verify_pw_by_byte(0, sn))//AC 0을 얻는다.
                {
                    return null;
                }
#endif //SUPPORT_FINGERPRINT
                //Thread.Sleep(1000);

                ictkpuf.puf_wakeup();
                byte[] read_data = ictkpuf._chip_read_key_for_byte(15, (int)P2OPTION.OPTION_LOWER_KEY_AREA);//4번키의 값을 읽는다. AC 1을 얻어야 한다. 

                if (read_data == null)
                {
                    return null;
                }

                _KEYCERT_HEADER KeyCertHeader = ByteToStruct<_KEYCERT_HEADER>(read_data);

               // Thread.Sleep(1000);

                byte[] CertData = new byte[(int)KeyCertHeader.cert_size];
                byte[] ConBineData = new byte[((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE) + ((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE)];
                ictkpuf.puf_wakeup();
                //Thread.Sleep(10);
                byte[] CertFirstData    = ictkpuf._chip_read_multi_key(0, (int)P2OPTION.OPTION_LOWER_DATA0_AREA, ((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE));
                ictkpuf.puf_wakeup();
                //Thread.Sleep(10);
                byte[] CertSecondData   = ictkpuf._chip_read_multi_key(0, (int)P2OPTION.OPTION_LOWER_DATA1_AREA, ((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE));
                //Thread.Sleep(10);
                Array.Clear(CertData, 0, CertData.Length);
                Array.Clear(ConBineData, 0, ConBineData.Length);
                Array.Copy(CertFirstData, 0, ConBineData, 0, CertFirstData.Length);
                Array.Copy(CertSecondData, 0, ConBineData, CertFirstData.Length, CertSecondData.Length);

                Array.Copy(ConBineData, 0, CertData , 0, (int)KeyCertHeader.cert_size);

                if (VerifySHA256ChceksumCert(CertData) == false)
                {
                    return null;
                }

                return CertData;
            }

#pragma warning disable CS0162 // 접근할 수 없는 코드가 있습니다.
            return null;
#pragma warning restore CS0162 // 접근할 수 없는 코드가 있습니다.
        }


        public string GetPUF_Cert_by_string()
        {
            byte[] prk = new byte[8];
            ictkpuf.puf_wakeup();
            var sn = ictkpuf.get_puf_sn_byte();
            ictkpuf.puf_wakeup();

            if (ictkpuf.is_puf_connect() != true)
            {
                return String.Empty;
            }
            else
            {
                Thread.Sleep(1);
                if(!ictkpuf.set_puf_aes_function(ICTK_ALGORITHM.aes_crypto, ICTK_ALGORITHM.sha_256))
                {
                    return string.Empty;
                }
#if SUPPORT_FINGERPRINT
#else //SUPPORT_FINGERPRINT
                Thread.Sleep(1);
                if (!ictkpuf._chip_verify_pw_by_byte(0, sn))
                {
                    for (int i = 0; i < 5; i ++ )
                    {
                        Thread.Sleep(10);
                        if (ictkpuf._chip_verify_pw_by_byte(0, sn))
                        {
                            break;
                        }

                    }

                    if (!ictkpuf._chip_verify_pw_by_byte(0, sn))
                    {
                        return String.Empty;
                    }
                }

                Thread.Sleep(1);
#endif
                //Thread.Sleep(1000);
                //ictkpuf.puf_wakeup();
                byte[] read_data = ictkpuf._chip_read_key_for_byte(15, (int)P2OPTION.OPTION_LOWER_KEY_AREA);//

                if (read_data == null)
                {
                    for (int i = 0; i < 5; i++)
                    {
                        Thread.Sleep(10);
                        read_data = ictkpuf._chip_read_key_for_byte(15, (int)P2OPTION.OPTION_LOWER_KEY_AREA);//
                        if (read_data != null)
                        {
                            break;
                        }
                    }
                    if (read_data == null)
                    {
                        return String.Empty;
                    }
                }


                _KEYCERT_HEADER KeyCertHeader = ByteToStruct<_KEYCERT_HEADER>(read_data);

                //Thread.Sleep(1000);

                byte[] CertData         = new byte[((int)KeyCertHeader.cert_size)];
                byte[] ConBineData      = new byte[(((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE) + ((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE ))];

                Thread.Sleep(1);
                //ictkpuf.puf_wakeup();
                byte[] CertFirstData    = ictkpuf._chip_read_multi_key(0, (int)P2OPTION.OPTION_LOWER_DATA0_AREA, ((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE));
                if (CertFirstData == null)
                {
                    for (int i = 0; i < 5; i ++)
                    {
                        Thread.Sleep(5);
                        CertFirstData = ictkpuf._chip_read_multi_key(0, (int)P2OPTION.OPTION_LOWER_DATA0_AREA, ((int)KeyCertHeader.cert_slot_size * PUF_SECTER_SIZE));
                        if (CertFirstData != null)
                        {
                            break;
                        }
                    }
                }
                //ictkpuf.puf_wakeup();
                Thread.Sleep(1);
                byte[] CertSecondData   = ictkpuf._chip_read_multi_key(0, (int)P2OPTION.OPTION_LOWER_DATA1_AREA,((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE));
                if (CertSecondData == null)
                {
                    for (int i = 0; i < 5; i++)
                    {
                        Thread.Sleep(5);
                        CertSecondData = ictkpuf._chip_read_multi_key(0, (int)P2OPTION.OPTION_LOWER_DATA1_AREA, ((int)KeyCertHeader.cert_slot2_size * PUF_SECTER_SIZE));
                        if (CertSecondData != null)
                        {
                            break;
                        }
                    }
                }

                if (CertFirstData == null || CertSecondData == null)
                {
                    return String.Empty;
                }

                Array.Clear(CertData, 0, CertData.Length);
                Array.Clear(ConBineData, 0, ConBineData.Length);
                Array.Copy(CertFirstData, 0, ConBineData, 0, CertFirstData.Length);
                Array.Copy(CertSecondData, 0, ConBineData, CertFirstData.Length, CertSecondData.Length);

                Array.Copy(ConBineData, 0, CertData, 0, (int)KeyCertHeader.cert_size);

                if (VerifySHA256ChceksumCert(CertData) == false)
                {
                    return string.Empty;
                }

                return String.Format("{0}", NeoHexString.ByteArrayToHexStr(CertData)); 
            }

#pragma warning disable CS0162 // 접근할 수 없는 코드가 있습니다.
            return String.Empty;
#pragma warning restore CS0162 // 접근할 수 없는 코드가 있습니다.
        }

        void IDisposable.Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
