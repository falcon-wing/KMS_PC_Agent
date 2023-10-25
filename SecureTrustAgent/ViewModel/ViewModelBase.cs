using SecureTrustAgent.Helpers;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureTrustAgent.ViewModel
{
    class ViewModelBase : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;

        TcpListener g_listener;
        Thread g_thread;
        /*
        TcpClient g_client;
        */
        UtilsClass utils = new UtilsClass();

        public void OnPropertyChanged(string propName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propName));
        }

        public ViewModelBase()
        {
            g_thread = new Thread(new ThreadStart(ListenRequests));
            g_thread.SetApartmentState(ApartmentState.STA);
            g_thread.IsBackground = true;
            g_thread.Start();
        }

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
                                    string serverMsg = string.Format("RECV=[username:{0}, ipaddress: {1}], SEND=[{2}]", split_data[0], split_data[1], serverResult);
                                    //MessageBox.Show(serverMsg);

                                    /*
                                    MFA_FingerPrintingView mFA_FingerPrintingView = new MFA_FingerPrintingView();
                                    mFA_FingerPrintingView.ShowDialog();

                                    if (mFA_FingerPrintingView.DialogResult.HasValue && mFA_FingerPrintingView.DialogResult.Value)
                                    {
                                        serverResult = "SUCCEED";
                                    }
                                    else
                                    {
                                        serverResult = "FAIL";

                                    }
                                    */
                                    byte[] serverMsgAsByteArray = Encoding.UTF8.GetBytes(serverResult);
                                    stream.Write(serverMsgAsByteArray, 0, serverMsgAsByteArray.Length);
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
                //MessageBox.Show("Socket exception " + sex.ToString());
            }
            catch (Exception ex)
            {
            }
        }
    }
}
