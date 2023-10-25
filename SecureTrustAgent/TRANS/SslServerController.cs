using CefSharp.DevTools.Target;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SecureTrustAgent.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static SecureTrustAgent.Helpers.DefineStruct;
using static SecureTrustAgent.JSON_DataClass;
using System.Windows.Threading;
using System.Collections;
using System.Diagnostics;

namespace SecureTrustAgent.TRANS
{
    internal class SslServerController
    {
        MainWindow _mainWindowObject;
        RestApiClass _restApi = new RestApiClass();
        public WebSocketState State { get; private set; } = WebSocketState.None;

        private readonly TcpClient targetClient;
        private readonly NetworkStream messageStream;
        private readonly StreamReader streamReader;
        private readonly SslStream _stream;
        private readonly byte[] dataBuffer = new byte[4096];
        static StringBuilder readData = new StringBuilder();
        static byte[] buffer = new byte[2048];

        public SslServerController() { }

        public SslServerController(TcpClient tcpClient, SslStream stream,MainWindow main)
        {
            this._mainWindowObject = main;
            targetClient = tcpClient;
            
            _stream = stream;
            //stream = targetClient.GetStream();
            stream.BeginRead(buffer, 0, buffer.Length, new AsyncCallback(ReadCallback), stream);
/*
            messageStream = targetClient.GetStream();
            messageStream.BeginRead(dataBuffer, 0, dataBuffer.Length, OnReadData, null);
*/
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

        private void HandshakeToClient(int dataSize, SslStream stream)
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

            string response2 = 
                "HTTP/1.1 101 Switching Protocols\r\n" +
                "Connection: Upgrade\r\n" +
                "Upgrade: websocket\r\n" +
                "Sec-WebSocket-Accept: " + swkaSha1Base64 + "\r\n\r\n";

            //Send request approval response
            StreamWriter sw = new StreamWriter(stream);
            sw.Write(response2);
            sw.Flush();

            //_stream.Write(response, 0, response.Length);
        }

        private bool ProcessClientSslRequest(string requestData, SslStream stream)
        {

            string TRID_STR = string.Empty;
            if (IsValidJson(requestData))
            {
                JObject json = JObject.Parse(requestData);

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

                    reqJson = JsonConvert.DeserializeObject<JSON_STGRUCT_OF_WEB_REQ_UID>(requestData);

                    System.Diagnostics.Debug.WriteLine("TRID : 500201" + "Data :" + requestData);

                    AGENT_INFO aGENT_INFO = new AGENT_INFO();
                    _mainWindowObject.get_agent_info(ref aGENT_INFO);

                    reqJson.header.trId = reqJson.header.trId;
                    reqJson.header.rtnMessage = reqJson.header.rtnMessage;
                    reqJson.header.rtnCode = reqJson.header.rtnCode;
                    reqJson.body.uid = aGENT_INFO.uid;
                    reqJson.body.pc_info = "";

                    string SendMsg = JsonConvert.SerializeObject(reqJson);
                    System.Diagnostics.Debug.WriteLine("TRID : 500202" + "SENDData :" + SendMsg);

                    byte[] message = Encoding.UTF8.GetBytes("hello~~~~~~~~~~~~~~~~");
                    StreamWriter sw = new StreamWriter(stream);
                    string sendlen = "Content-Length:" + SendMsg.Length + "\r\n";
                    sw.Write("HTTP/1.0 200 OK\r\n");
                    sw.Write("Conenction: close\r\n");
                    sw.Write("Content-Type: text/plain\r\n");
                    sw.Write(sendlen);
                    sw.Write("\r\n");
                    sw.Write(SendMsg);
                    sw.Flush();
                    //stream.Flush();
                }));
                //stream.Flush();
                //stream.Close();

                return true;
            }

            /*
            // TRID : 500202
            */
            comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_PC_WEB_LOGIN, comparisonType: StringComparison.OrdinalIgnoreCase);

            /*
             * TRID : 500204
             */
            comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_REQUEST_AUTH, comparisonType: StringComparison.OrdinalIgnoreCase);

            /*
             * TRID : 500205
             */
            comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_REQUEST_REGPUF, comparisonType: StringComparison.OrdinalIgnoreCase);

            /*
             * TRID : 500206
             */
            comparison = String.Compare(/*jSON_STRUCT_OF_WEB.Header.trid*/TRID_STR, Trid.TRID_REQUEST_RESETPUF, comparisonType: StringComparison.OrdinalIgnoreCase);

            /*
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
                            //SendCloseRequest(1000, "Graceful Close");
                            State = WebSocketState.Closed;
                        }
                        //Dispose();      // socket close
                        return false;
                    default:
                        //Console.WriteLine("Unknown Data Type");
                        break;
                }

                if (bResult == true)
                {
                    //#if _NEW
                    string TRID_STR = string.Empty;
                    if (IsValidJson(sResponseData))
                    {
                        JObject json = JObject.Parse(sResponseData);

                        JToken jUser = json["header"];
                        TRID_STR = (string)jUser["trId"];

                    }
                }

            }
        */
            stream.Flush();
            return true;
        }

        public void SendData(byte[] data, PayloadDataType opcode)
        {
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

                _stream.Write(sendData, 0, sendData.Length);  //클라이언트에 전송
                _stream.Flush();
            }
            catch (Exception e)
            {
                string errmsg = "There was a problem with the operation in progress... [SendData][" + e.Message + "]";
                //common.Log_info(errmsg, (int)LOGINFO.ERROR, (int)LOGINFO_FUNCTION.WEBSOCKET);

                Debug.WriteLine(e.Message);
            }
        }


        private void ReadCallback(IAsyncResult ar)
        {
            // Read the  message sent by the server.
            // The end of the message is signaled using the
            // "<EOF>" marker.
            SslStream stream = (SslStream)ar.AsyncState;
            int byteCount = -1;
            try
            {
                
                Console.WriteLine("Reading data from the server.");
                byteCount = stream.EndRead(ar);
//                HandshakeToClient(byteCount, stream);

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, byteCount)];
                decoder.GetChars(buffer, 0, byteCount, chars, 0);
                readData.Append(chars);
                
                if (new System.Text.RegularExpressions.Regex("^GET").IsMatch(readData.ToString()))
                {
                    const string eol = "\r\n"; // HTTP/1.1 defines the sequence CR LF as the end-of-line marker

                    byte[] response = Encoding.UTF8.GetBytes("HTTP/1.1 101 Switching Protocols" + eol
                        + "Connection: Upgrade" + eol
                        + "Upgrade: websocket" + eol
                        + "Sec-WebSocket-Accept: " + Convert.ToBase64String(
                            System.Security.Cryptography.SHA1.Create().ComputeHash(
                                Encoding.UTF8.GetBytes(
                                    new System.Text.RegularExpressions.Regex("Sec-WebSocket-Key: (.*)").Match(readData.ToString()).Groups[1].Value.Trim() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                                )
                            )
                        ) + eol
                    + eol);

                    stream.Write(response, 0, response.Length);
                    
                }

                Console.WriteLine(readData.ToString());
                /*
                // Check for EOF or an empty message.
                if (readData.ToString().IndexOf("<EOF2>") == -1 && byteCount != 0)
                {
                    // We are not finished reading.
                    // Asynchronously read more message data from  the server.
                    stream.BeginRead(buffer, 0, buffer.Length,
                        new AsyncCallback(ReadCallback),
                        stream);
                }
                else
                {
                    Console.WriteLine("Message from the server: {0}", readData.ToString());

                    string ReadData = readData.ToString();

                    int nStart = ReadData.IndexOf("<EOF1>");
                    string str1 = ReadData.Substring(nStart + 6);
                    string sResponseData = str1.Replace("<EOF2>", " ");

                    

                    //SendData(Encoding.UTF8.GetBytes(sResponseData), PayloadDataType.Text);

                    if (ProcessClientSslRequest(sResponseData, stream) == false) {
                        return; }

                    readData.Clear();
                }
                */
                stream.BeginRead(buffer, 0, buffer.Length,
                        new AsyncCallback(ReadCallback),
                        stream);

            }
            catch (Exception readException)
            {
               // e = readException;
               // complete = true;
                return;
            }
            //complete = true;
        }

        private void OnReadData(IAsyncResult ar)
        {
            SslStream stream = (SslStream)ar.AsyncState;
            int byteCount = -1;
            try
            {
                Console.WriteLine("Reading data from the server.");
                byteCount = stream.EndRead(ar);
                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, byteCount)];
                decoder.GetChars(buffer, 0, byteCount, chars, 0);
                readData.Append(chars);
                // Check for EOF or an empty message.
                if (readData.ToString().IndexOf("<EOF>") == -1 && byteCount != 0)
                {
                    // We are not finished reading.
                    // Asynchronously read more message data from  the server.
                    stream.BeginRead(buffer, 0, buffer.Length,
                        new AsyncCallback(ReadCallback),
                        stream);
                }
                else
                {
                    Console.WriteLine("Message from the server: {0}", readData.ToString());
                }
            }
            catch (Exception readException)
            {
                //e = readException;
                //complete = true;
                return;
            }
        }

    }
}
