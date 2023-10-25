using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Diagnostics;



namespace SecureTrustAgent.TRANS
{

    class WebServerSockClass 
    {
        static X509Certificate serverCertificate = null;
        private readonly TcpListener _listener;
        MainWindow _mainWin;
        List<TcpClient> listConnectedClients = new List<TcpClient>();


        public WebServerSockClass(IPAddress address, int port, MainWindow mainWin)
        {
            //public TcpClient connectedClients = new List<TcpClient>();
            //serverCertificate = new X509Certificate(certificate, password);

            _listener = new TcpListener(address, port);
            _listener.Start();

            _listener.BeginAcceptSocket(OnAcceptClient, null);
            _mainWin = mainWin;
        }

        private void OnAcceptClient(IAsyncResult ar)
        {
            TcpClient client = _listener.EndAcceptTcpClient(ar);

            listConnectedClients.Add(client);

            WebSocketController webSocketController = new WebSocketController(client, _mainWin);

            //SslServerClass wdbSSLServer = new SslServerClass();
            
            _listener.BeginAcceptTcpClient(OnAcceptClient, null);
        }

        private void DisconnectClient(int ip, int port)
        {
            //listConnectedClients.RemoveRange(ip, port);
        }
    }
}
