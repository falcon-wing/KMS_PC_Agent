
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using CefSharp.DevTools.Debugger;
using System.IO;
using System.Runtime.ConstrainedExecution;

namespace SecureTrustAgent.TRANS
{
    internal class SslServerClass
    {
        static X509Certificate serverCertificate = null;
        static X509Certificate2 certificate2 = null;
        private readonly TcpListener _listener;
        List<TcpClient> listConnectedClients = new List<TcpClient>();
        MainWindow _mainWin;

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

        public SslServerClass(IPAddress address, int port, MainWindow mainWin, string certificate, string password)
        {
            certificate2 = new X509Certificate2(certificate, password);
            _listener = new TcpListener(address, port);
            _listener.Start();

            _listener.BeginAcceptSocket(OnAcceptClient, null);
            _mainWin = mainWin;

            //RunServer(certificate, password);
        }

        public bool WebSocketHandshake(Stream clientStream)
        {
            string hellostr;

            // Here I test trying to get data (Also tried to use Stream.ReadByte())
            Byte[] toto = new Byte[2048];

            ((SslStream)clientStream).Read(toto, 0, 2048);

            if (toto[0] == 0) return false;

            Console.WriteLine("#############################################");
            Console.WriteLine("toto array is {0} bytes long", toto.Length);
            for (int t = 0; t < 10; t++)
            {
                for (int u = 0; u < 10; u++)
                {
                    Console.Write(toto[t * 10 + u].ToString());
                }
                Console.WriteLine(";");
            }
            Console.WriteLine("#############################################");

            // Trying to get data

            //hellostr=streamReadLine(clientStream);     

            //Console.WriteLine(hellostr);

            return true;
        }

        bool bConnect = false;
        private void OnAcceptClient(IAsyncResult ar)
        
        {
            
            TcpClient client = _listener.EndAcceptTcpClient(ar);
            NetworkStream netstream = client.GetStream();
            SslStream stream = new SslStream(client.GetStream(), false);

            try
            {

                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                stream.AuthenticateAsServer(certificate2, false, SslProtocols.Tls12, true);
                

                listConnectedClients.Add(client);


                SslServerController SslSocketController = new SslServerController(client, stream, _mainWin);
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
            }


            _listener.BeginAcceptTcpClient(OnAcceptClient, null);
        }


        public static void RunServer(string certificate, string password)
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                certificate2 = new X509Certificate2(certificate, password);
                
             //   serverCertificate = new X509Certificate(certificate, password);

                TcpListener listener = new TcpListener(IPAddress.Any, 8082);
                listener.Start();

                while (true)
                {
                    Console.WriteLine("Waiting for a client to connect...");
                    Console.WriteLine();

                    TcpClient client = listener.AcceptTcpClient();
                    ProcessClient(client);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(string.Format("Error : {0}", ex.Message));
            }
        }

        static void ProcessClient(TcpClient client)
        {
            SslStream sslStream = new SslStream(client.GetStream(), false);

            for (; ; )
            {
                try
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    sslStream.AuthenticateAsServer(certificate2, false, SslProtocols.Tls12 | SslProtocols.Tls13, false);

                    
                    StreamReader sr = new StreamReader(sslStream);
                    string line;
                    while ((line = sr.ReadLine()) != null && !line.Equals(""))
                    {
                        Console.WriteLine("received: " + line);
                    }
                    StreamWriter sw = new StreamWriter(sslStream);
                    sw.Write("HTTP/1.0 200 OK\r\n");
                    sw.Write("Conenction: close\r\n");
                    sw.Write("Content-Type: text/plain\r\n");
                    sw.Write("Content-Length: 5\r\n");
                    sw.Write("\r\n");
                    sw.Write("hello");
                    sw.Flush();
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine("Authentication failed - closing the connection.");
                   // sslStream.Close();
                   // client.Close();
                   // return;
                }
                finally
                {
                    // The client stream will be closed with the sslStream
                    // because we specified this behavior when creating
                    // the sslStream.
                    sslStream.Close();
                   // client.Close();
                }
            }
        }

        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the client.
            // The client signals the end of the message using the
            // "$" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                // Read the client's test message.
                bytes = sslStream.Read(buffer, 0, buffer.Length);

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for EOF or an empty message.
                if (messageData.ToString().IndexOf("$") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }
    }
}
