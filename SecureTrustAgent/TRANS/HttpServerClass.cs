using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using System.Windows;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static SecureTrustAgent.JSON_DataClass;
using SecureTrustAgent.Helpers;
using static SecureTrustAgent.Helpers.DefineStruct;
using CefSharp.DevTools.Network;
using NeoLib.Util;
using System.Security.Cryptography;
using CefSharp.JavascriptBinding;
using System.Net.Sockets;
using CefSharp;

namespace SecureTrustAgent.TRANS
{
    internal class HttpServerClass
    {
        private HttpListener _listener;
        private MainWindow _mainWindowObject;
        RestApiClass _restApi = new RestApiClass();
        bool g_bIsMastKeyUpdataWork = false;
        public string _listenPort;
        public LogClass _log = new LogClass();
        public HttpServerClass(IPAddress address, int port, MainWindow mainWin)
        {
            _mainWindowObject = mainWin;
            _listenPort = port.ToString();
            StartHttpListener();
        }
        private async void StartHttpListener()
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add("http://*:8080/"); // 원하는 포트 및 경로로 변경 가능
            string strListenPort = string.Empty;
            if (!string.IsNullOrEmpty(_listenPort))
            {
                strListenPort = "https://+:" + _listenPort + "/";
                _listener.Prefixes.Add(strListenPort);
            }
            
            _listener.AuthenticationSchemes = AuthenticationSchemes.Anonymous;
            var clientDisconnectTokenFactory = new ClientDisconnectTokenFactory(_listener);

            try
            {
                _listener.Start();

                while (_listener.IsListening)
                {
                    HttpListenerContext context = await _listener.GetContextAsync();
                    ThreadPool.QueueUserWorkItem(ProcessRequest, context);

                    var clientDisconnect = clientDisconnectTokenFactory.GetClientDisconnectToken(context.Request);
                }
            }
            catch (Exception ex)
            {
            }
        }

        private void StopHttpListener()
        {
            if (_listener != null && _listener.IsListening)
            {
                _listener.Stop();
                _listener.Close();
            }
        }
        private string get_req_data_string(HttpListenerContext context)
        {
            string str_req_data = string.Empty;
            using (var body = context.Request.InputStream)
            {
                var encoding = context.Request.ContentEncoding;
                var reader = new StreamReader(body, encoding);

                str_req_data = reader.ReadToEnd();

                reader.Close();
            }

            return str_req_data;
        }
        
        public bool send_result_msg(HttpListenerResponse stream, string msg)
        {
            bool bRet = false;
            byte[] buffer = Encoding.UTF8.GetBytes(msg);
            stream.ContentType = "text/html";
            stream.ContentLength64 = buffer.Length;

            Stream output = stream.OutputStream;
            output.Write(buffer, 0, buffer.Length);
            output.Close();

            return bRet;
        }

        public string get_errret_msg(string sTrid)
        {
            string strRetMsg = string.Empty;
            ICTK_JSON_RES_ERROR_RET errRet = new ICTK_JSON_RES_ERROR_RET();
            errRet.header.trId = sTrid;
            errRet.header.rtnCode = RET_CODE.RET_CODE_ERR;
            errRet.header.rtnMessage = RET_MSG.RET_MSG_ERR;
            strRetMsg = JsonConvert.SerializeObject(errRet);
            GC.SuppressFinalize(errRet);

            return strRetMsg;
        }

        private string get_reponse_data(string sTrid, string reqdata, HttpListenerContext context)
        {
            string sResultData = string.Empty;
            HttpListenerResponse response = context.Response;
            ICTK_HASH ictk_hash = new ICTK_HASH();
            string sLogData = string.Empty;

            int comparison = String.Compare(sTrid, Trid.TRID_GET_PCAGENT_INFO, comparisonType: StringComparison.OrdinalIgnoreCase);
            if (comparison == 0)
            {
                _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                {
                    if (_mainWindowObject.chk_puf_connected())
                    {
                        JSON_STGRUCT_OF_WEB_REQ_UID reqJson = new JSON_STGRUCT_OF_WEB_REQ_UID();
                        JSON_STGRUCT_OF_WEB_REQ_UID resJson = new JSON_STGRUCT_OF_WEB_REQ_UID();

                        reqJson = JsonConvert.DeserializeObject<JSON_STGRUCT_OF_WEB_REQ_UID>(reqdata);

                        reqJson.header.trId = reqJson.header.trId;
                        reqJson.header.rtnMessage = reqJson.header.rtnMessage;
                        reqJson.header.rtnCode = reqJson.header.rtnCode;
                        reqJson.body.uid = _mainWindowObject.getstring_sn_number();
                        reqJson.body.pc_info = "";

                        sResultData = JsonConvert.SerializeObject(reqJson);
                        
                        send_result_msg(response, sResultData);
                    }
                    else
                    {
                        _mainWindowObject.g_bIsSignin = false;
                        var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.OK);
                    }
                }));
            }

            comparison = String.Compare(sTrid, Trid.TRID_MASTERKEY_UPDATE, comparisonType: StringComparison.OrdinalIgnoreCase);
            if (comparison == 0)
            {
                _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                {
                    if (g_bIsMastKeyUpdataWork == false)
                    {
                        g_bIsMastKeyUpdataWork = true;
                        ICTK_JSON_REQ_MASTERKEY_UPDATE reqMastkeyUpdate = new ICTK_JSON_REQ_MASTERKEY_UPDATE();
                        ICTK_JSON_RES_MASTERKEY_UPDATE resMastkeyUpdate = new ICTK_JSON_RES_MASTERKEY_UPDATE();
                        reqMastkeyUpdate = JsonConvert.DeserializeObject<ICTK_JSON_REQ_MASTERKEY_UPDATE>(reqdata);

                        if (_mainWindowObject.Request_AdminPage_FingerPrintAuthentication_v2() == false)
                        {
                            sResultData = get_errret_msg(Trid.TRID_MASTERKEY_UPDATE);
                        }
                        else
                        {
                            sLogData = string.Format("The following request has been received on the web page. [{0}]", Trid.TRID_MASTERKEY_UPDATE);
                            _log.Log_info(sLogData, (int)LOGINFO.INFO);

                            _mainWindowObject.ictk_puf_api.get_permission_of_puf();
                            _mainWindowObject.ictk_puf_api.g3berify_fingerprintf_of_puf();
                            resMastkeyUpdate.header.trId = Trid.TRID_MASTERKEY_UPDATE;
                            resMastkeyUpdate.header.rtnCode = RET_CODE.RET_CODE_OK;
                            resMastkeyUpdate.header.rtnMessage = RET_MSG.RET_MSG_OK;

                            resMastkeyUpdate.body.challenge_1 = reqMastkeyUpdate.body.challenge_1;
                            resMastkeyUpdate.body.access_value_1 = _mainWindowObject.get_hmac_signature("secure", reqMastkeyUpdate.body.challenge_1); ;

                            resMastkeyUpdate.body.challenge_2 = reqMastkeyUpdate.body.challenge_2;
                            resMastkeyUpdate.body.access_value_2 = _mainWindowObject.get_hmac_signature("secure", reqMastkeyUpdate.body.challenge_2); ;

                            sLogData = string.Format("The web page request has been successfully completed. [{0}]", Trid.TRID_MASTERKEY_UPDATE);
                            _log.Log_info(sLogData, (int)LOGINFO.INFO);

                            sResultData = JsonConvert.SerializeObject(resMastkeyUpdate);
                        }
                        
                        send_result_msg(response, sResultData);
                        g_bIsMastKeyUpdataWork = false;
                    }
                }));
            }

            comparison = String.Compare(sTrid, Trid.TRID_PC_WEB_LOGIN, comparisonType: StringComparison.OrdinalIgnoreCase);
            if (comparison == 0)
            {
                _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(async () =>
                {
                    JSON_STGRUCT_OF_WEB_2ND reqJson = new JSON_STGRUCT_OF_WEB_2ND();
                    JSON_STGRUCT_OF_WEB_2ND resJson = new JSON_STGRUCT_OF_WEB_2ND();
                    
                    reqJson = JsonConvert.DeserializeObject<JSON_STGRUCT_OF_WEB_2ND>(reqdata);

                    if (reqJson.Body.mfa.mfaOption == (int)MFA_OPT_ENUM.MFA_OPT_AUTH)
                    {
                        sLogData = string.Format("The following request has been received on the web page. [{0}]", MFA_OPT_ENUM.MFA_OPT_AUTH);
                        _log.Log_info(sLogData, (int)LOGINFO.INFO);

                        //_mainWindowObject.ictk_puf_api.chipinit()
                        if (_mainWindowObject.Request_AdminPage_FingerPrintAuthentication_v2() == false)
                        {
                            _mainWindowObject.g_bIsSignin = false;
                            var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG_V2, MessageBoxButton.OK);

                            sResultData = get_errret_msg(DefineString.WEBREQ_JSON_TRID_AUTH);
                            send_result_msg(response, sResultData);

                            sLogData = string.Format("The fingerprint authentication operation has failed. [{0}]", MFA_OPT_ENUM.MFA_OPT_AUTH);
                            _log.Log_info(sLogData, (int)LOGINFO.ERROR);
                        }
                        else
                        {
                            string sn = _mainWindowObject.getstring_sn_number();
                            _mainWindowObject.g_bIsSignin = true;
                            _mainWindowObject.ShowWaitingWindow();
                            var Puf_Prk = await _mainWindowObject.collect_puf_prk();
                            _mainWindowObject.CloseWaitingWindow();

                            if (Puf_Prk != null)
                            {
                                sLogData = string.Format("The fingerprint authentication operation was successful. [{0}]", MFA_OPT_ENUM.MFA_OPT_AUTH);
                                _log.Log_info(sLogData, (int)LOGINFO.INFO);

                                var sign_data = _mainWindowObject.sign_signature(reqJson.Body.mfa.challenge, reqJson.Body.mfa.challenge.Length, Puf_Prk);

                                if (sign_data != null)
                                {
                                    sLogData = string.Format("The request for a signature to the server was successful.");
                                    _log.Log_info(sLogData, (int)LOGINFO.INFO);

                                    string signature = NeoHexString.ByteArrayToHexStr(sign_data);
                                    JSON_RES_AUTH_STRUCT resAuthJson = new JSON_RES_AUTH_STRUCT();
                                    ICTK_JSON_AUTH_STRUCT reqAuth = new ICTK_JSON_AUTH_STRUCT();

                                    reqAuth.header.trId = DefineString.WEBREQ_JSON_TRID_AUTH;
                                    reqAuth.body.uId = _mainWindowObject.getstring_sn_number();
                                    reqAuth.body.sessionId = reqJson.Body.mfa.sessionId;

                                    reqAuth.body.signature.pqc.signAlgorithm = "dilithium2";
                                    reqAuth.body.signature.pqc.signature = signature;

                                    if (_restApi.httpWebRequest_auth(reqAuth, ref resAuthJson, reqJson.Body.mfa.token.accessToken,
                                                reqJson.Body.mfa.sessionId) == true)
                                    {
                                        ICTK_JSON_RES_SESSION_KEY_CHALLENGE_STATUCT jsonResKeyChallenge = new ICTK_JSON_RES_SESSION_KEY_CHALLENGE_STATUCT();
                                        ICTK_JSON_REQ_SESSION_KEY_CHALLENGE_STRUCT jsonReqSkChallenge = new ICTK_JSON_REQ_SESSION_KEY_CHALLENGE_STRUCT();
                                        jsonReqSkChallenge.header.trId = DefineString.WEBREQ_JSON_TRID_SESSIONKEY_CHALLENGE;
                                        jsonReqSkChallenge.body.uId = _mainWindowObject.getstring_sn_number();
                                        jsonReqSkChallenge.body.sessionId = resAuthJson.body.sessionId;

                                        sLogData = string.Format("Receiving authentication information from the web browser to initiate the authentication process with the server.");
                                        _log.Log_info(sLogData, (int)LOGINFO.INFO);


                                        if (_restApi.httpWebRequest_sessionkey_challenge(jsonReqSkChallenge, ref jsonResKeyChallenge, resAuthJson.body.agentToken.accessToken, resAuthJson.body.sessionId))
                                        {
                                            ICTK_JSON_REQ_SESSION_KEY_REQUEST_STATUCT jsonReqKeyRequest = new ICTK_JSON_REQ_SESSION_KEY_REQUEST_STATUCT();
                                            ICTK_JSON_RES_SESSION_KEY_REQUEST_STATUCT jsonResKeyRequest = new ICTK_JSON_RES_SESSION_KEY_REQUEST_STATUCT();

                                            jsonReqKeyRequest.header.trId = DefineString.WEBREQ_JSON_TRID_SESSIONKEY_REQUEST;
                                            jsonReqKeyRequest.body.uId = _mainWindowObject.getstring_sn_number();
                                            jsonReqKeyRequest.body.sessionId = jsonResKeyChallenge.body.sessionId;

                                            sLogData = string.Format("The session key exchange operation was successful.");
                                            _log.Log_info(sLogData, (int)LOGINFO.INFO);

                                            byte[] enc_key = new byte[2 * 1088], share_key = new byte[2048],
                                            out_data = new byte[3094], share_key_bak = new byte[32];

                                            bool result = _mainWindowObject.process_pqc_kem_enc(enc_key, share_key, NeoHexString.StringToByteArray(jsonResKeyChallenge.body.kePk));
                                            if (result == true)
                                            {
                                                Array.Copy(share_key, share_key_bak, 32);
                                                jsonReqKeyRequest.body.encKey = NeoHexString.ByteArrayToHexStr(enc_key);
                                                string sarekey = NeoHexString.ByteArrayToHexStr(share_key_bak);

                                                if (_restApi.httpWebRequest_sessionkey_request(jsonReqKeyRequest, ref jsonResKeyRequest, resAuthJson.body.agentToken.accessToken, resAuthJson.body.sessionId))
                                                {
                                                    sLogData = string.Format("The request for session key information to the server was successful.");
                                                    _log.Log_info(sLogData, (int)LOGINFO.INFO);

                                                    ICTK_JSON_RES_SESSION_KEY_RESULT_STRUCT jsonResSessionKeyResult = new ICTK_JSON_RES_SESSION_KEY_RESULT_STRUCT();
                                                    byte[] Byte_encSessionKey = Convert.FromBase64String(jsonResKeyRequest.body.encSessionKey);

                                                    byte[] Byte_encSessionKey_bak = new byte[32];
                                                    Array.Copy(Byte_encSessionKey, Byte_encSessionKey_bak, 32);

                                                    byte[] byte_dec_Sessionkey = EncryptionAndDecryption.aes_decrypt(Byte_encSessionKey_bak, share_key_bak);

                                                    string strSessionKey = NeoHexString.ByteArrayToHexStr(byte_dec_Sessionkey);

                                                    jsonResSessionKeyResult.header.trId = Trid.TRID_PC_WEB_LOGIN;
                                                    jsonResSessionKeyResult.header.rtnMessage = RET_MSG.RET_MSG_OK;
                                                    jsonResSessionKeyResult.header.rtnCode = RET_CODE.RET_CODE_OK;

                                                    jsonResSessionKeyResult.body.sessionKey = strSessionKey;
                                                    jsonResSessionKeyResult.body.browserToken.uId = jsonReqKeyRequest.body.uId;
                                                    jsonResSessionKeyResult.body.browserToken.accessToken = resAuthJson.body.browserToken.accessToken;
                                                    jsonResSessionKeyResult.body.browserToken.expired = resAuthJson.body.browserToken.expired;
                                                    jsonResSessionKeyResult.body.browserToken.expiredCount = resAuthJson.body.browserToken.expiredCount;

                                                    sResultData = JsonConvert.SerializeObject(jsonResSessionKeyResult);

                                                    send_result_msg(response, sResultData);

                                                    _mainWindowObject.g_strLastLoginUserID = reqJson.Body.userId;
                                                    _mainWindowObject.g_strLastLoginPufUID = jsonReqKeyRequest.body.uId;

                                                    sLogData = string.Format("The session key information has been delivered to the web browser.");
                                                    _log.Log_info(sLogData, (int)LOGINFO.INFO);

                                                    sLogData = string.Format("The authentication process was successful.");
                                                    _log.Log_info(sLogData, (int)LOGINFO.INFO);
                                                }
                                            }else
                                            {
                                                sLogData = string.Format("The authentication process has failed. The request for session key information to the server has failed.");
                                                _log.Log_info(sLogData, (int)LOGINFO.ERROR);
                                                sResultData = get_errret_msg(DefineString.WEBREQ_JSON_TRID_AUTH);
                                                send_result_msg(response, sResultData);
                                            }
                                        }
                                        else
                                        {
                                            sLogData = string.Format("The authentication process has failed. The session key exchange operation has failed.");
                                            _log.Log_info(sLogData, (int)LOGINFO.ERROR);
                                            sResultData = get_errret_msg(DefineString.WEBREQ_JSON_TRID_AUTH);
                                            send_result_msg(response, sResultData);
                                        }
                                    }
                                    else
                                    {
                                        sLogData = string.Format("The authentication process has failed. The web page authentication process has failed.");
                                        _log.Log_info(sLogData, (int)LOGINFO.ERROR);

                                        sResultData = get_errret_msg(DefineString.WEBREQ_JSON_TRID_AUTH);
                                        send_result_msg(response, sResultData);
                                    }
                                }
                                else
                                {
                                    sLogData = string.Format("The authentication process has failed. The request for a signature to the server has failed.");
                                    _log.Log_info(sLogData, (int)LOGINFO.ERROR);

                                    sResultData = get_errret_msg(DefineString.WEBREQ_JSON_TRID_AUTH);
                                    send_result_msg(response, sResultData);
                                }
                            }
                        }
                    }

                    else if (reqJson.Body.mfa.mfaOption == (int)MFA_OPT_ENUM.MFA_OPT_REGPUF)
                    {
                        if (_mainWindowObject.ictk_puf_api.enrolled_fingerprint() != true)
                        {
                            

                            _mainWindowObject.RequestFingerPrintRegistration();
                            bool bRet = _mainWindowObject.ictk_puf_api.macverify_fingerprintf_of_puf();
                            if (bRet != true) {
                                var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFAREG_FAILTITLE, Localization.res.STR_FAIL_AND_RETRY_REG_MSG, MessageBoxButton.OK);

                                sLogData = string.Format("The registration process has failed. The fingerprint registration process has failed.");
                                _log.Log_info(sLogData, (int)LOGINFO.ERROR);

                                sResultData = get_errret_msg(DefineString.WEBREQ_JSON_TRID_AUTH);
                                send_result_msg(response, sResultData);
                            }
                        }
                        else {

                            if (_mainWindowObject.Request_AdminPage_FingerPrintAuthentication_v2() == false)
                            {
                                _mainWindowObject.g_bIsSignin = false;
                            }
                        }

                        sLogData = string.Format("The fingerprint registration process was successful.");
                        _log.Log_info(sLogData, (int)LOGINFO.INFO);

                        _mainWindowObject.ictk_puf_api.get_permission_of_puf();

                        bool test =_mainWindowObject.ictk_puf_api.macverify_fingerprintf_of_puf();
                        byte[] bytes = _mainWindowObject.ictk_puf_api.g3berify_fingerprintf_of_puf();

                        JSON_STGRUCT_OF_WEB_2ND Json = new JSON_STGRUCT_OF_WEB_2ND();
                        Json = JsonConvert.DeserializeObject<JSON_STGRUCT_OF_WEB_2ND>(reqdata);

                        JSON_STRUCT_OF_WEB req_jSON = new JSON_STRUCT_OF_WEB();
                        JSON_STRUCT_OF_WEB res_jSON = new JSON_STRUCT_OF_WEB();

                        AGENT_INFO aGENT_INFO = new AGENT_INFO();

                        _mainWindowObject.ShowWaitingWindow();
                        _mainWindowObject.get_agent_info(ref aGENT_INFO);
                        _mainWindowObject.CloseWaitingWindow();

                        string[] TarApi = REQUEST_API_STRUCT.request_api[(int)APIINDEX.INDEX_PUF_REG];

                        req_jSON.header.trId = TarApi[(int)API_ITEM.ITEM_TRID];
                        req_jSON.header.Authorization = Json.Header.Authorization;

                        req_jSON.body.uId = aGENT_INFO.uid;
                        req_jSON.body.userId = Json.Body.userId;
                        req_jSON.body.crt = aGENT_INFO.crt;
                        req_jSON.body.sessionId = Json.Body.mfa.sessionId;
                        req_jSON.body.mfa.token.accessToken = Json.Body.mfa.token.accessToken;
                        
                        sLogData = string.Format("Requesting registration of the PUF USB in the system.");
                        _log.Log_info(sLogData, (int)LOGINFO.INFO);

                        if (_restApi.httpWebRequest((int)APIINDEX.INDEX_PUF_REG, req_jSON, ref res_jSON) == false)
                        {
                            sLogData = string.Format("The server registration process has failed.");
                            _log.Log_info(sLogData, (int)LOGINFO.ERROR);

                            sResultData = get_errret_msg(DefineString.WEBREQ_JSON_TRID_AUTH);
                            send_result_msg(response, sResultData);
                        }
                        else
                        {
                            ICTK_JSON_RES_RESET_RET resWebRet = new ICTK_JSON_RES_RESET_RET();

                            resWebRet.header.trId = Trid.TRID_PC_WEB_LOGIN;
                            resWebRet.header.rtnCode = RET_CODE.RET_CODE_OK;
                            resWebRet.header.rtnMessage = RET_MSG.RET_MSG_OK;

                            resWebRet.body.uId = aGENT_INFO.uid;
                            resWebRet.body.mfaOption = reqJson.Body.mfa.mfaOption;

                            sResultData = JsonConvert.SerializeObject(resWebRet);

                            sLogData = string.Format("The server registration process was successful.");
                            _log.Log_info(sLogData, (int)LOGINFO.INFO);

                            send_result_msg(response, sResultData);
                        }
                    }
                    else if (reqJson.Body.mfa.mfaOption == (int)MFA_OPT_ENUM.MFA_OPT_RESET)
                    {
                        ICTK_JSON_REQ_RESET_SIGNATURE jsonReqResetSig = new ICTK_JSON_REQ_RESET_SIGNATURE();
                        ICTK_JSON_RES_RESET_SIGNATURE jsonResResetSig = new ICTK_JSON_RES_RESET_SIGNATURE();
                        
                        if (_mainWindowObject.Request_AdminPage_FingerPrintAuthentication_v2() == false)
                        {
                            _mainWindowObject.g_bIsSignin = false;
                        }

                        jsonReqResetSig.header.trId = DefineString.WEBREQ_JSON_TRID_RESET_SIGNATURE;
                        jsonReqResetSig.body.uId = _mainWindowObject.getstring_sn_number();
                        jsonReqResetSig.body.rand = _mainWindowObject.getstring_pufchallenge();
                        
                        if (_restApi.httpWebRequest_reset_signature(jsonReqResetSig, ref jsonResResetSig, reqJson.Body.mfa.token.accessToken, reqJson.Body.mfa.sessionId))
                        {
                            bool bRet = _mainWindowObject.ictk_puf_api.get_permission_of_puf();
                            string challenge = jsonReqResetSig.body.rand;//_mainWindowObject.pufClass.get_challenge_in_puf();
                            _mainWindowObject.pufClass.puf_wakeup();
                            bRet = _mainWindowObject.pufClass.remove_fingerprint_template_in_puf();
                            if (bRet == true)
                            {
                                /*
                                _mainWindowObject.pufClass.puf_wakeup();
                                string sign = jsonResResetSig.body.sign;
                                bRet = _mainWindowObject.pufClass.chip_reset_puf(NeoHexString.HexStringToByteArray(challenge), NeoHexString.HexStringToByteArray(sign));
                                if (bRet == true)
                                {
                                }
                                else
                                {
                                }
                                */
                                ICTK_JSON_RES_RESET_FIN reqFinJson = new ICTK_JSON_RES_RESET_FIN();
                                ICTK_JSON_RES_RESET_FIN resFinJson = new ICTK_JSON_RES_RESET_FIN();

                                reqFinJson.header.trId = "070231";
                                reqFinJson.body.uId = jsonReqResetSig.body.uId;
                                _restApi.httpWebRequest_reset_fin(reqFinJson, ref resFinJson, reqJson.Body.mfa.token.accessToken, reqJson.Body.mfa.sessionId);

                                ICTK_JSON_RES_RESET_RET resWebRet = new ICTK_JSON_RES_RESET_RET();

                                resWebRet.header.trId       = Trid.TRID_PC_WEB_LOGIN;
                                resWebRet.header.rtnCode    = RET_CODE.RET_CODE_OK;
                                resWebRet.header.rtnMessage = RET_MSG.RET_MSG_OK;

                                resWebRet.body.uId = jsonReqResetSig.body.uId;
                                resWebRet.body.mfaOption = reqJson.Body.mfa.mfaOption;

                                sResultData = JsonConvert.SerializeObject(resWebRet);

                                send_result_msg(response, sResultData);

                            }
                        }
                    }
                }));
            
            }

            return sResultData;
        }

        private void ProcessRequest(object state)
        {
            HttpListenerContext context = (HttpListenerContext)state;
            HttpListenerRequest request = context.Request;
            HttpListenerResponse response = context.Response;
            string responseString = string.Empty;
            string sendmsg = string.Empty;

            if (request.HttpMethod == "OPTIONS")
            {
                response.AddHeader("Access-Control-Allow-Headers", "Content-Type, Accept, X-Requested-With");
                response.AddHeader("Access-Control-Allow-Methods", "GET, POST");
                response.AddHeader("Access-Control-Max-Age", "1728000");
            }

            response.AppendHeader("Access-Control-Allow-Origin", "*");

            var httpMethod = request.HttpMethod.ToLower();
            var actionName = request.Url?.AbsolutePath;
            var queryString = request.QueryString;

            Console.WriteLine("ProcessRequest.... call\n");

            string sResponseData = string.Empty;
            string TRID_STR = string.Empty;
            string sResultData = string.Empty;

            try
            {

                switch (actionName)
                {
                   
                    case "/puf/get-information" when httpMethod is "post":
                    case "/puf/weblogin" when httpMethod is "post":
                    case "/puf/masterkey-update" when httpMethod is "post":
                    case "/test1" when httpMethod is "post":
                        {
                            sResponseData = get_req_data_string(context);
                            if (sResponseData != string.Empty)
                            {
                                if (IsValidJson(sResponseData))
                                {
                                    JObject json = JObject.Parse(sResponseData);

                                    JToken jUser = json["header"];
                                    TRID_STR = (string)jUser["trId"];
                                }

                                sResultData = get_reponse_data(TRID_STR, sResponseData, context);
                            }
                        }
                        break;
                    case "/puf/get-information" when httpMethod is "options":
                    case "/puf/get-information" when httpMethod is "options":
                    case "/puf/weblogin" when httpMethod is "options":
                    case "/puf/masterkey-update" when httpMethod is "options":
                    case "/test1" when httpMethod is "options":
                        byte[] buffer = Encoding.UTF8.GetBytes(sResultData);
                        Stream output = response.OutputStream;
                        output.Write(buffer, 0, buffer.Length);
                        output.Close();
                        break;
                    default:
                        sResponseData = get_req_data_string(context);
                        Console.WriteLine("ProcessRequest.... default" + httpMethod + sResponseData);
                        
                        break;
                }
            }
            catch (Exception ex)
            {
            }
        }

        private static bool IsValidJson(string strInput)
        {
            if (string.IsNullOrWhiteSpace(strInput)) { return false; }
            strInput = strInput.Trim();
            if ((strInput.StartsWith("{") && strInput.EndsWith("}")) || //For object
                (strInput.StartsWith("[") && strInput.EndsWith("]"))) //For array
            {
                try
                {
                    var obj = JToken.Parse(strInput);
                    return true;
                }
                catch (JsonReaderException jex)
                {
                    //Exception in parsing json
                    Console.WriteLine(jex.Message);
                    return false;
                }
                catch (Exception ex) //some other exception
                {
                    Console.WriteLine(ex.ToString());
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
    }
}
