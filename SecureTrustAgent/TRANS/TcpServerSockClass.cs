using SecureTrustAgent.Helpers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace SecureTrustAgent.TRANS
{
    public class TcpServerSockClass
    {
        bool g_bServerRun = false;
        TcpListener g_listener;
        Thread g_thread;
        //TcpClient g_client;
        UtilsClass utils = new UtilsClass();
        MainWindow main;

        /// <summary>
        /// 
        /// </summary>
        public TcpServerSockClass(MainWindow main) 
        {
            this.main = main;
            //ServerStart();
        }

        private int RunProcess(String FileName, String Args)
        {
            Process p = new Process();

            p.StartInfo.FileName = FileName;
            p.StartInfo.Arguments = Args;

            p.StartInfo.WindowStyle = ProcessWindowStyle.Normal;

            p.Start();
            p.WaitForExit();

            return p.ExitCode;
        }
        /// <summary>
        /// 
        /// </summary>
        public void ServerStart ()
        {
            if (g_bServerRun == false)
            {
                g_thread = new Thread(new ThreadStart(ListenRequests));
                g_thread.SetApartmentState(ApartmentState.STA);
                g_thread.IsBackground = true;
                g_thread.Start();
            }
        }

        private void A_myEvent(object sender, EventArgs e)
        {
            MessageBox.Show("recv event~~~");
        }
        /// <summary>
        /// 
        /// </summary>
        private void ListenRequests()
        {
            //Socket clientsocket = null;
            //StreamReader reader = null;
            TcpClient client = null;

            try
            {
                IPAddress iPAddress = IPAddress.Any;
                string strListenPort = utils.get_conf(DefineString.SSH_LISTEN_PORT, DefineString.SSH_SECTION);
                g_listener = new TcpListener(iPAddress, Convert.ToInt32(strListenPort));
                g_listener.Start();

                Byte[] bytes = new byte[DefineString.MAX_BUFFER_SIZE];

                while (true)
                {
                    using (client = g_listener.AcceptTcpClient())
                    {
                        using (NetworkStream stream = client.GetStream())
                        {
                            int length;
                            try
                            {
                                while ((length = stream.Read(bytes, 0, bytes.Length)) != 0)
                                {
                                    var incomingData = new Byte[length];
                                    Array.Copy(bytes, 0, incomingData, 0, length);
                                    string clientMsg = Encoding.UTF8.GetString(incomingData);

                                    string[] split_data = clientMsg.Split('|');
                                    string serverResult = "";
                                    //int num = 999;
                                    string serverMsg = string.Format("RECV=[username:{0}, ipaddress: {1}], SEND=[{2}]", split_data[0], split_data[1], serverResult);
                                    /*
                                    serverResult = "SUCCEED";
                                    
                                    byte[] serverMsgAsByteArray = Encoding.UTF8.GetBytes(serverResult);
                                    stream.Write(serverMsgAsByteArray, 0, serverMsgAsByteArray.Length);
                                    */
                                    //main.ExcuteWebLogViewofSSH(client);
                                    main.ExcuteWebLogViewofSSH_V2(client);
                                    /*
                                    WebViewWindow webViewWindow = new WebViewWindow();
                                    webViewWindow.ShowInTaskbar = true;
                                    webViewWindow.Visibility = Visibility.Visible;
                                    webViewWindow.WindowState = WindowState.Normal;
                                    webViewWindow.Topmost = true;
                                    webViewWindow.myEvent += A_myEvent;
                                    webViewWindow.ShowDialog();
                                   
                                    if (webViewWindow.DialogResult.HasValue && webViewWindow.DialogResult.Value)
                                    {

                                    } */
                                    //serverResult = "FAIL";

                                    /*
                                    MFA_FP_Window LoginDlg = new MFA_FP_Window();
                                    LoginDlg.ShowInTaskbar = true;
                                    LoginDlg.Visibility = Visibility.Visible;
                                    LoginDlg.WindowState = WindowState.Normal;
                                    LoginDlg.Topmost = true;
                                    
                                    LoginDlg.ShowDialog();

                                    if (LoginDlg.DialogResult.HasValue && LoginDlg.DialogResult.Value)
                                    {
                                        serverResult = "SUCCEED";
                                    }
                                    else
                                    {
                                        serverResult = "FAIL";
                                    }
                                    

                                    byte[] serverMsgAsByteArray = Encoding.UTF8.GetBytes(serverResult);
                                    stream.Write(serverMsgAsByteArray, 0, serverMsgAsByteArray.Length);
                                    */
                                }
                            }
                            catch {
                                client.Close();
                            }
                        }
                    }
                }
            }
            catch (SocketException sex)
            {
                MessageBox.Show("Socket exception " + sex.ToString());
            }
            catch (Exception ex)
            {
                MessageBox.Show("Socket exception " + ex.ToString());
            }
        }
    }
}
