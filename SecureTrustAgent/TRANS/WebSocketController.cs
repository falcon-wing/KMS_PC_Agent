using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.ToolTip;
using System.Windows.Forms;
using System.Collections;
using SecureTrustAgent.Properties;
using System.Windows.Documents;
using System.Windows;
using MessageBox = System.Windows.Forms.MessageBox;
using System.Windows.Threading;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static SecureTrustAgent.JSON_DataClass;
using SecureTrustAgent.Helpers;
using System.Net;
using System.Diagnostics;
using static SecureTrustAgent.Helpers.DefineStruct;
using CefSharp.DevTools.Target;
using NeoLib.Util;

namespace SecureTrustAgent.TRANS
{
    public enum PayloadDataType
    {   //RFC 6455 기반
        Unknown = -1,
        Continuation = 0,
        Text = 1,
        Binary = 2,
        ConnectionClose = 8,
        Ping = 9,
        Pong = 10
    }

    public class resJsonInfo
    {
        //public string[] header
    }

    public class WebSocketController
    {
        MainWindow _mainWindowObject;
        RestApiClass _restApi = new RestApiClass();

        public WebSocketState State { get; private set; } = WebSocketState.None;

        private readonly TcpClient targetClient;
        private readonly NetworkStream messageStream;
        private readonly byte[] dataBuffer = new byte[1024];

        public WebSocketController() { }

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

        public bool ParseComment(string jsonData)
        {
            // var objs = JsonConvert.DeserializeObject<JArray>(jsonData);
            JSON_STRUCT_OF_WEB jSON_STRUCT_OF_WEB = new JSON_STRUCT_OF_WEB();
            jSON_STRUCT_OF_WEB = JsonConvert.DeserializeObject<JSON_STRUCT_OF_WEB>(jsonData);

            jSON_STRUCT_OF_WEB = JsonConvert.DeserializeObject<JSON_STRUCT_OF_WEB>(jsonData);
            if (string.Compare( jSON_STRUCT_OF_WEB.header.rtnCode, DefineString.WEB_JSON_SUCCESS_RETCODE) == 0 && 
                string.Compare(jSON_STRUCT_OF_WEB.header.rtnMessage, DefineString.WEB_JSON_SUCCESS_RETMSG) == 0)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="tcpClient"></param>
        public WebSocketController(TcpClient tcpClient)
        {
            State = WebSocketState.Connecting;  //It's not a full WebSocket connection, so it shows Connecting

            targetClient = tcpClient;
            
            messageStream = targetClient.GetStream();

            messageStream.BeginRead(dataBuffer, 0, dataBuffer.Length, OnReadData, null);
        }

        public WebSocketController(TcpClient tcpClient,MainWindow main)
        {
            this._mainWindowObject = main;
            targetClient = tcpClient;
            messageStream = targetClient.GetStream();
            messageStream.BeginRead(dataBuffer, 0, dataBuffer.Length, OnReadData, null);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ar"></param>
        private void OnReadData(IAsyncResult ar)
        {
            int size = messageStream.EndRead(ar);   //End of data reception

            byte[] httpRequestRaw = new byte[7];    //The HTTP request method does not exceed 7 digits...
                                                    //You only need to check GET, so it doesn't matter if you use new byte[3]
            Array.Copy(dataBuffer, httpRequestRaw, httpRequestRaw.Length);
            string httpRequest = Encoding.UTF8.GetString(httpRequestRaw);

            //Check if this is a GET request
            if (Regex.IsMatch(httpRequest, "^GET", RegexOptions.IgnoreCase))
            {
                HandshakeToClient(size);        // Response to connection request
                State = WebSocketState.Open;    // Transition status to Connecting with a successful response
            }
            else
            {
                //Processing of message reception, return value is whether or not the connection is closed
                if (ProcessClientRequest(size) == false) { return; }
            }
            //Restart data reception
            messageStream.BeginRead(dataBuffer, 0, dataBuffer.Length, OnReadData, null);
        }


        private void p_Exited(object sender, EventArgs e)
        {
            MessageBox.Show("Process exited");
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="dataSize"></param>
        /// <returns></returns>
        private bool ProcessClientRequest(int dataSize)
        {
            bool fin = (dataBuffer[0] & 0b10000000) != 0;   // If it is false, it should be processed to connect to the next data.
            bool mask = (dataBuffer[1] & 0b10000000) != 0;  // Unconditionally true if received from the client
            PayloadDataType opcode = (PayloadDataType)(dataBuffer[0] & 0b00001111); // convert to enum

            int msglen = dataBuffer[1] - 128; // Performed under the assumption that the mask bit is unconditionally 1
            int offset = 2;     //data starting point
            if (msglen == 126)  //For length 126 or more
            {
                // Transformed by reversing the byte order of the buffer since it was sent in big - endian format and C# uses little-endian.
                msglen = BitConverter.ToInt16(new byte[] { dataBuffer[3], dataBuffer[2] }, 0);
                
                offset = 4;
            }
            else if (msglen == 127)
            {
                Console.WriteLine("Error: over int16 size");
                return true;
            }

            if (mask)
            {
                byte[] decoded = new byte[msglen];
                //Obtain the masking key
                byte[] masks = new byte[4] { dataBuffer[offset], dataBuffer[offset + 1], dataBuffer[offset + 2], dataBuffer[offset + 3] };
                offset += 4;

                for (int i = 0; i < msglen; i++)    //remove mask
                {
                    decoded[i] = (byte)(dataBuffer[offset + i] ^ masks[i % 4]);
                }

                string sResponseData = System.Text.Encoding.UTF8.GetString(decoded, 0, decoded.Length);
                bool bResult = false;

                switch (opcode)
                {
                    case PayloadDataType.Text:
                        bResult = true;
                        
                        break;
                    case PayloadDataType.Binary: 
                        //Binary does nothing
                        break;
                    case PayloadDataType.ConnectionClose:
                        // Run only if the received request is not a response to a request sent by the serve
                        if (State != WebSocketState.CloseSent)
                        {
                            SendCloseRequest(1000, "Graceful Close");
                            State = WebSocketState.Closed;
                        }
                        Dispose();      // socket close
                        return false;
                    default:
                        //Console.WriteLine("Unknown Data Type");
                        break;
                }

                if (bResult == true)
                {
                    string TRID_STR = string.Empty;
                    if (IsValidJson(sResponseData))
                    {
                        JObject json = JObject.Parse(sResponseData);

                        JToken jUser = json["header"];
                        TRID_STR = (string)jUser["trId"];

                    }

                    /*
                    // TRID : 500201
                    */
                    int comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_GET_PCAGENT_INFO, comparisonType: StringComparison.OrdinalIgnoreCase);
                    if (comparison == 0)
                    {
                        _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                        {
                            JSON_STGRUCT_OF_WEB_REQ_UID reqJson = new JSON_STGRUCT_OF_WEB_REQ_UID();
                            JSON_STGRUCT_OF_WEB_REQ_UID resJson = new JSON_STGRUCT_OF_WEB_REQ_UID();

                            reqJson = JsonConvert.DeserializeObject<JSON_STGRUCT_OF_WEB_REQ_UID>(sResponseData);

                            System.Diagnostics.Debug.WriteLine("TRID : 500201" + "Data :" + sResponseData);

                            AGENT_INFO aGENT_INFO = new AGENT_INFO();
                            _mainWindowObject.get_agent_info(ref aGENT_INFO);

                            reqJson.header.trId = reqJson.header.trId;
                            reqJson.header.rtnMessage = reqJson.header.rtnMessage;
                            reqJson.header.rtnCode = reqJson.header.rtnCode;
                            reqJson.body.uid = aGENT_INFO.uid;
                            reqJson.body.pc_info = "";

                            string SendMsg = JsonConvert.SerializeObject(reqJson);
                            System.Diagnostics.Debug.WriteLine("TRID : 500202" + "SENDData :" + SendMsg);
                            SendData(Encoding.UTF8.GetBytes(SendMsg), PayloadDataType.Text);
                        }));

                        return true; 
                    }

                    /*
                    // TRID : 500202
                    */
                    comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_PC_WEB_LOGIN, comparisonType: StringComparison.OrdinalIgnoreCase);
                    if (comparison == 0)
                    {
                        _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(async () =>
                        {
                            JSON_STGRUCT_OF_WEB_2ND reqJson = new JSON_STGRUCT_OF_WEB_2ND();
                            JSON_STGRUCT_OF_WEB_2ND resJson = new JSON_STGRUCT_OF_WEB_2ND();
                            reqJson = JsonConvert.DeserializeObject<JSON_STGRUCT_OF_WEB_2ND>(sResponseData);

                            if (reqJson.Body.mfa.mfaOption == (int)MFA_OPT_ENUM.MFA_OPT_AUTH)
                            {
                                if (_mainWindowObject.Request_AdminPage_FingerPrintAuthentication_v2() == false)
                                {
                                    _mainWindowObject.g_bIsSignin = false;
                                }

                                AGENT_INFO aGENT_INFO = new AGENT_INFO();
                                _mainWindowObject.get_agent_info(ref aGENT_INFO);

                                var Puf_Prk = await _mainWindowObject.collect_puf_prk();
                                if (Puf_Prk != null)
                                {
                                    var sign_data = _mainWindowObject.sign_signature(reqJson.Body.mfa.challenge, reqJson.Body.mfa.challenge.Length, Puf_Prk);

                                    if (sign_data != null)
                                    {
                                        string signature = NeoHexString.ByteArrayToHexStr(sign_data);
                                        JSON_RES_AUTH_STRUCT resAuthJson = new JSON_RES_AUTH_STRUCT();
                                        ICTK_JSON_AUTH_STRUCT reqAuth = new ICTK_JSON_AUTH_STRUCT();
                                        
                                        reqAuth.header.trId = DefineString.WEBREQ_JSON_TRID_AUTH;
                                        reqAuth.body.uId = _mainWindowObject.getstring_sn_number();
                                        reqAuth.body.sessionId = reqJson.Body.mfa.sessionId;
                                        //reqAuth.body.signature.ecc.signAlgorithm = "ecdsa_with_sha256";

                                        reqAuth.body.signature.pqc.signAlgorithm = "dillithium2";
                                        reqAuth.body.signature.pqc.signature = signature;


                                        if (_restApi.httpWebRequest_auth(reqAuth, ref resAuthJson, reqJson.Body.mfa.token.accessToken,
                                            reqJson.Body.mfa.sessionId) == true)
                                        {
                                            //SEND TOKEN TO BROWSER

                                            //request challenge
                                            ICTK_JSON_RES_SESSION_KEY_CHALLENGE_STATUCT jsonResKeyChallenge = new ICTK_JSON_RES_SESSION_KEY_CHALLENGE_STATUCT();
                                            ICTK_JSON_REQ_SESSION_KEY_CHALLENGE_STRUCT jsonReqSkChallenge = new ICTK_JSON_REQ_SESSION_KEY_CHALLENGE_STRUCT();
                                            jsonReqSkChallenge.header.trId = DefineString.WEBREQ_JSON_TRID_SESSIONKEY_CHALLENGE;
                                            jsonReqSkChallenge.body.uId = _mainWindowObject.getstring_sn_number();
                                            jsonReqSkChallenge.body.sessionId = resAuthJson.body.sessionId;

                                            if (_restApi.httpWebRequest_sessionkey_challenge(jsonReqSkChallenge, ref jsonResKeyChallenge, reqJson.Body.mfa.token.accessToken, reqJson.Body.mfa.sessionId))
                                            {
                                                ICTK_JSON_REQ_SESSION_KEY_REQUEST_STATUCT jsonReqKeyRequest = new ICTK_JSON_REQ_SESSION_KEY_REQUEST_STATUCT();
                                                ICTK_JSON_RES_SESSION_KEY_REQUEST_STATUCT jsonResKeyRequest = new ICTK_JSON_RES_SESSION_KEY_REQUEST_STATUCT();

                                                jsonReqKeyRequest.header.trId = DefineString.WEBREQ_JSON_TRID_SESSIONKEY_REQUEST;
                                                jsonReqKeyRequest.body.uId = _mainWindowObject.getstring_sn_number();
                                                jsonReqKeyRequest.body.sessionId= resAuthJson.body.sessionId;

                                                byte[] enc_key = new byte[2 * 1088], share_key = new byte[2048],
                                                out_data = new byte[3094], share_key_bak = new byte[32];

                                                bool result = _mainWindowObject.process_pqc_kem_enc(enc_key, share_key, NeoHexString.StringToByteArray(jsonResKeyChallenge.body.kePk));
                                                if (result == true) {
                                                    Array.Copy(share_key, share_key_bak, 32);

                                                    jsonReqKeyRequest.body.encKey = NeoHexString.ByteArrayToHexStr(enc_key);
                                                }


                                                if (_restApi.httpWebRequest_sessionkey_request(jsonReqKeyRequest, ref jsonResKeyRequest, reqJson.Body.mfa.token.accessToken, reqJson.Body.mfa.sessionId))
                                                {

                                                    byte[] Byte_encSessionKey = Convert.FromBase64String(jsonResKeyRequest.body.encSessionKey);
                                                    byte[] byte_dec_Sessionkey = EncryptionAndDecryption.aes_decrypt(Byte_encSessionKey, share_key_bak);

                                                    string strSessionKey = NeoHexString.ByteArrayToHexStr(byte_dec_Sessionkey);

                                                    
                                                    //>> WEB 에게 전달 필요
                                                }
                                            }
                                            else
                                            {

                                            }

                                            //request session key

                                            //인증 결과 전다ㅏㄹ
                                        }
                                        else                                        {
                                            // ERROR
                                        }
                                    }
                                    else                                    {
                                        //ERROR
                                    }
                                }
                            }
                            else if (reqJson.Body.mfa.mfaOption == (int)MFA_OPT_ENUM.MFA_OPT_REGPUF)
                            {
                                    
                                /*if (_mainWindowObject.RequestFingerPrint_reRegistration() == false)
                                {
                                    _mainWindowObject.g_bIsSignin = false;
                                }

                                */
                                JSON_STGRUCT_OF_WEB_2ND Json = new JSON_STGRUCT_OF_WEB_2ND();
                                Json = JsonConvert.DeserializeObject<JSON_STGRUCT_OF_WEB_2ND>(sResponseData);

                                JSON_STRUCT_OF_WEB req_jSON = new JSON_STRUCT_OF_WEB();
                                JSON_STRUCT_OF_WEB res_jSON = new JSON_STRUCT_OF_WEB();

                                AGENT_INFO aGENT_INFO = new AGENT_INFO();
                                _mainWindowObject.get_agent_info(ref aGENT_INFO);

                                string[] TarApi = REQUEST_API_STRUCT.request_api[(int)APIINDEX.INDEX_PUF_REG];

                                req_jSON.header.trId = TarApi[(int)API_ITEM.ITEM_TRID];
                                req_jSON.header.Authorization = Json.Header.Authorization;

                                req_jSON.body.uId = aGENT_INFO.uid;
                                req_jSON.body.userId = Json.Header.userId;
                                req_jSON.body.crt = aGENT_INFO.crt;
                                req_jSON.body.sessionId = Json.Body.mfa.sessionId;
                                req_jSON.body.mfa.token.accessToken = Json.Body.mfa.token.accessToken;

                                _restApi.httpWebRequest((int)APIINDEX.INDEX_PUF_REG, req_jSON, ref res_jSON);
                            }
                            else if (reqJson.Body.mfa.mfaOption == (int)MFA_OPT_ENUM.MFA_OPT_RESET)
                            {
                                ICTK_JSON_REQ_RESET_SIGNATURE jsonReqResetSig = new ICTK_JSON_REQ_RESET_SIGNATURE();
                                ICTK_JSON_RES_RESET_SIGNATURE jsonResResetSig = new ICTK_JSON_RES_RESET_SIGNATURE();
                                _mainWindowObject.RequestFingerPrint_signout_puf();

                                jsonReqResetSig.header.trId = DefineString.WEBREQ_JSON_TRID_RESET_SIGNATURE;
                                jsonReqResetSig.body.uId = _mainWindowObject.getstring_sn_number();
                                jsonReqResetSig.body.rand = _mainWindowObject.getstring_pufrand(128);

                                if (_restApi.httpWebRequest_reset_signature(jsonReqResetSig, ref jsonResResetSig, reqJson.Body.mfa.token.accessToken, reqJson.Body.mfa.sessionId)  )
                                {
                                    //PUF 초기화 작업 진행
                                    
                                }
                            }
                            else
                            {
                            }
                            SendData(Encoding.UTF8.GetBytes(sResponseData), PayloadDataType.Text);
                        }));

                        return true;
                    }

                    /*
                     * TRID : 500204
                     */
                    comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_REQUEST_AUTH, comparisonType: StringComparison.OrdinalIgnoreCase);
                    if (comparison == 0)
                    {
                        _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                        {
                        }));

                        return true;
                    }

                    /*
                     * TRID : 500205
                     */
                    comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_REQUEST_REGPUF, comparisonType: StringComparison.OrdinalIgnoreCase);
                    if (comparison == 0)
                    {
                        _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                        {
                            if (_mainWindowObject.Request_AdminPage_FingerPrintAuthentication_v2() == false)
                            {
                                _mainWindowObject.g_bIsSignin = false;
                            }

                            JSON_STGRUCT_OF_WEB_2ND Json = new JSON_STGRUCT_OF_WEB_2ND();
                            Json = JsonConvert.DeserializeObject<JSON_STGRUCT_OF_WEB_2ND>(sResponseData);

                            JSON_STRUCT_OF_WEB req_jSON = new JSON_STRUCT_OF_WEB();
                            JSON_STRUCT_OF_WEB res_jSON = new JSON_STRUCT_OF_WEB();

                            AGENT_INFO aGENT_INFO = new AGENT_INFO();
                            _mainWindowObject.get_agent_info(ref aGENT_INFO);

                            string[] TarApi = REQUEST_API_STRUCT.request_api[(int)APIINDEX.INDEX_PUF_REG];

                            req_jSON.header.trId = TarApi[(int)API_ITEM.ITEM_TRID];
                            req_jSON.header.Authorization = Json.Header.Authorization;

                            req_jSON.body.uId = aGENT_INFO.uid;
                            req_jSON.body.userId = Json.Header.userId;
                            req_jSON.body.crt = aGENT_INFO.crt;
                            req_jSON.body.sessionId = Json.Body.mfa.sessionId;
                            req_jSON.body.mfa.token.accessToken = Json.Body.mfa.token.accessToken;

                            _restApi.httpWebRequest((int)APIINDEX.INDEX_PUF_REG, req_jSON, ref res_jSON);
                        }));
                        return true;
                    }

                    /*
                     * TRID : 500206
                     */
                    comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_REQUEST_RESETPUF, comparisonType: StringComparison.OrdinalIgnoreCase);
                    if (comparison == 0)
                    {
                        _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                        {
                            _mainWindowObject.RequestFingerPrint_signout_puf();
                        }));

                        return true;
                    }

                    /*
                     * TRID : 500207
                     */
                    comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_SSH_LOGIN, comparisonType: StringComparison.OrdinalIgnoreCase);
                    if (comparison == 0)
                    {
                        _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                        {
                            if (_mainWindowObject.Request_SSH_FingerPrintAuthentication_v2() == false)
                            {
                            }
                            else
                            {
                                SendData(Encoding.UTF8.GetBytes("SSHAuth_Success"), PayloadDataType.Text);
                            }
                        }));

                        return true;
                    }

                    /*
                     * TRID : 500208
                     */
                    comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_WEB_LOGOUT, comparisonType: StringComparison.OrdinalIgnoreCase);
                    if (comparison == 0)
                    {
                        _mainWindowObject.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
                        {
                            _mainWindowObject.RequestFingerPrint_logoff();
                        }));

                        return true;
                    }
                }
            }
            else
            {
                // Masking check failed
                // Console.WriteLine("Error: Mask bit not valid");
            }

            return true;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="opcode"></param>
        public void SendData(byte[] data, PayloadDataType opcode)
        {
#if NEW_TYPE
            byte[] sendData;
            BitArray firstByte = new BitArray(new bool[] {
                    // opcode
                    opcode == PayloadDataType.Text || opcode == PayloadDataType.Ping,
                    opcode == PayloadDataType.Binary || opcode == PayloadDataType.Pong,
                    false,
                    opcode == PayloadDataType.ConnectionClose || opcode == PayloadDataType.Ping || opcode == PayloadDataType.Pong,
                    false,  //RSV3
                    false,  //RSV2
                    false,  //RSV1
                    true,   //Fin
                });

            if (data.Length < 126)
            {
                sendData = new byte[data.Length + 2];
                firstByte.CopyTo(sendData, 0);
                sendData[1] = (byte)data.Length;    // Mask bit must be 0 on the server
                data.CopyTo(sendData, 2);
            }
            else
            {
                // As with reception, it cannot respond to data with a length of 32,767 or more (in the range of int16 or more).
                sendData = new byte[data.Length + 4];
                firstByte.CopyTo(sendData, 0);
                sendData[1] = 126;
                byte[] lengthData = BitConverter.GetBytes((ushort)data.Length);
                Array.Copy(lengthData, 0, sendData, 2, 2);
                data.CopyTo(sendData, 4);
            }

            messageStream.Write(sendData, 0, sendData.Length);  // send to client
#endif
            byte[] sendData;
            BitArray firstByte = new BitArray(new bool[] {
                    // opcode
                    opcode == PayloadDataType.Text || opcode == PayloadDataType.Ping,
                    opcode == PayloadDataType.Binary || opcode == PayloadDataType.Pong,
                    false,
                    opcode == PayloadDataType.ConnectionClose || opcode == PayloadDataType.Ping || opcode == PayloadDataType.Pong,
                    false,  //RSV3
                    false,  //RSV2
                    false,  //RSV1
                    true,   //Fin
                });

            try
            {
                if (data.Length < 126)
                {
                    sendData = new byte[data.Length + 2];
                    firstByte.CopyTo(sendData, 0);
                    sendData[1] = (byte)data.Length;    //서버에서는 Mask 비트가 0이어야 함
                    data.CopyTo(sendData, 2);
                }
                else
                {
                    sendData = new byte[data.Length + 4];
                    firstByte.CopyTo(sendData, 0);
                    sendData[1] = 126;
                    var lengthData = BitConverter.GetBytes((ushort)data.Length);
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(lengthData);
                    }

                    Array.Copy(lengthData, 0, sendData, 2, 2);
                    data.CopyTo(sendData, 4);
                }

                messageStream.Write(sendData, 0, sendData.Length);  //클라이언트에 전송
                messageStream.Flush();
            }
            catch (Exception e)
            {
                string errmsg = "There was a problem with the operation in progress... [SendData][" + e.Message + "]";
                //common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.WEBSOCKET);

                Debug.WriteLine(e.Message);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="code"></param>
        /// <param name="reason"></param>
        public void SendCloseRequest(ushort code, string reason)
        {
            byte[] closeReq = new byte[2 + reason.Length];
            BitConverter.GetBytes(code).CopyTo(closeReq, 0);
            //In Chrome, the code can be properly recognized only when the place is changed.
            byte temp = closeReq[0];
            closeReq[0] = closeReq[1];
            closeReq[1] = temp;
            Encoding.UTF8.GetBytes(reason).CopyTo(closeReq, 2);
            SendData(closeReq, PayloadDataType.ConnectionClose);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dataSize"></param>
        private void HandshakeToClient(int dataSize)
        {
            string raw = Encoding.UTF8.GetString(dataBuffer);

            string swk = Regex.Match(raw, "Sec-WebSocket-Key: (.*)").Groups[1].Value.Trim();
            string swka = swk + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            byte[] swkaSha1 = System.Security.Cryptography.SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(swka));
            string swkaSha1Base64 = Convert.ToBase64String(swkaSha1);

            // HTTP/1.1 defines consecutive CR and LF as markers indicating the end of a line.
            byte[] response = Encoding.UTF8.GetBytes(
                "HTTP/1.1 101 Switching Protocols\r\n" +
                "Connection: Upgrade\r\n" +
                "Upgrade: websocket\r\n" +
                "Sec-WebSocket-Accept: " + swkaSha1Base64 + "\r\n\r\n");

            //Send request approval response
            messageStream.Write(response, 0, response.Length);
        }
        
        /// <summary>
        /// 
        /// </summary>
        public void Dispose()
        {
            targetClient.Close();
            targetClient.Dispose(); // Freeing all socket related resources
        }
    }
}
