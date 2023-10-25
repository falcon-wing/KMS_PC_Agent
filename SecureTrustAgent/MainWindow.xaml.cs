using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Forms;
using MessageBox = System.Windows.Forms.MessageBox;
using System.Runtime.InteropServices;
using ContextMenu = System.Windows.Forms.ContextMenu;
using SecureTrustAgent.Helpers;
using System.Net.Sockets;
using System.Threading;
using System.Windows.Controls;
using System.IO;

using System.Net;
using SecureTrustAgent.TRANS;
//using System.Runtime.InteropServices;
using System.Windows.Interop;
using System.Windows.Threading;
using System.Runtime.InteropServices.ComTypes;
using System.Net.NetworkInformation;
using System.Diagnostics;
using System.Net.Http;
//using SecureTrustAgent.Helpers;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Windows.Automation;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.Tab;
using System.Collections;
using static SecureTrustAgent.Helpers.DefineStruct;
using pqcclrwrap;
using System.Data.SqlTypes;
using NeoLib.Util;
using static SecureTrustAgent.Helpers.ictk_puf_warpper;
using System.Security.RightsManagement;
using MaterialDesignThemes.Wpf;
using System.ComponentModel;
using Path = System.IO.Path;
using System.Collections.ObjectModel;

///

namespace SecureTrustAgent
{

    public struct COPYDATASTRUCT
    {
        public IntPtr dwData;
        public UInt32 cbData;
        [MarshalAs(UnmanagedType.LPStr)]
        public string lpData;
    }

    public enum FP_WORK_TYPE
    {
        INDEX_FP_WORK_ENROLL = 1,
        INDEX_FP_WORK_VERIFY = 2,
    }

    public enum FP_WORK_RESULT
    {
        INDEX_FP_WORK_SUCCESS = 0,
        INDEX_FP_WORK_FAIL = 1,
    }

    public enum WORK_WINDOW_TYPE
    {
        INDEX_WORK_SIGNIN = 0,
        INDEX_WORK_SIGNOUT  ,
        INDEX_WORK_SIGNUP   ,
        INDEX_WORK_RESIGNUP ,
    }

    public  class Auth_Status
    {
        public string Title { get; set; } = "Login and PUF information";
    }

   


    /// <summary>
    /// MainWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class MainWindow : Window
    {
        bool g_bExitApp = false;
        bool g_bSupportssh = false;
        public const Int32 WM_COPYDATA = 0x004A;
        public bool g_bIsSignin = false;
        private System.Windows.Forms.NotifyIcon _trayIcon;
        TcpServerSockClass TcpServer;// = new TcpServerSockClass();
        WebServerSockClass WebServer;
        HttpServerClass httpServer;
        public ObservableCollection<string> puf_sn_string;
        WaitingWindow wating;// = new WaitingWindow();

        public string g_strLastLoginPufUID;
        public string g_strLastLoginUserID;

        SslServerClass SslServer;

        public string xml_puf_tooltitle = "Login and PUF information";
        /*
        private readonly TcpListener _listener;
        */
        public UtilsClass utils = new UtilsClass();
        WebViewWindow webLobinView = null;
        ICTK_HASH ictk_hash = new ICTK_HASH();

        TcpClient g_SshClientSocket = null;
        public ICTK_PUF ictk_puf_api = new ICTK_PUF();
        public IctkPufClass pufClass = new IctkPufClass();
        ictk_puf_warpper pufwarpper = new ictk_puf_warpper();

        int INowWorkWindowType = 0;

        MFA_FP_Window g_current_mfa = null;
        Mfa_worksignout_window g_current_signout_Window = null;
        Mfa_workregistration_window g_current_signup_Window = null;
        Mfa_work_re_registration_window g_current_re_signup_Window = null;

        delegate bool EnumWindowsProc(IntPtr hWnd, int lParam);

        bool g_bWebAdminPageWorking = false;

        [DllImport("user32.dll")]
        private static extern bool EnumDesktopWindows(IntPtr hDesktop, EnumWindowsProc ewp, int lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        static extern bool GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        [DllImport("user32.dll")]
        private static extern uint GetWindowText(IntPtr hWnd, StringBuilder lpString, uint nMaxCount);

        [DllImport("user32.dll")]
        private static extern uint GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
        
        bool g_bExistNowMfaWork = false;
        /*
        Process g_IctkAdminBrouse = null;
        */
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SendMessage(IntPtr hWnd, UInt32 Msg, IntPtr wParam, ref COPYDATASTRUCT lParam);
        private const int MINIMUM_SPLASH_TIME = 5000; // Miliseconds
#if _NOTUSE_CLASS
        TcpListener g_listener;
        Thread g_thread;
        TcpClient g_client;
        UtilsClass utils = new UtilsClass();
#endif
        public event System.Windows.RoutedEventHandler Opened;



        // public ICommand TooltipOpenCommand => new RelayCommand(ToolTipOpen);
        /// <summary>
        /// 
        /// </summary>
        public MainWindow()
        {


            System.Windows.Data.Binding bind = new System.Windows.Data.Binding();
            /*bind.Source = AuthInfoToolTipTitle;
            bind.Path = new PropertyPath(TextBlock.TextProperty);
            AuthInfoToolTipTitle.SetBinding()
            */
            this.Title = "SecureTrustAgent";
            Localization.res.Culture = Properties.Settings.Default.language != string.Empty ?
                                        new System.Globalization.CultureInfo(Properties.Settings.Default.language) : System.Globalization.CultureInfo.CurrentCulture;
            Duplicate_execution(Title);
            //InitializeComponent();
            WindowStartupLocation = System.Windows.WindowStartupLocation.CenterScreen;
#if _NOTUSE_CLASS
            g_thread = new Thread(new ThreadStart(ListenRequests));
            g_thread.SetApartmentState(ApartmentState.STA);
            g_thread.IsBackground = true;
            g_thread.Start();
#else
            SflashWindowClass splash = new SflashWindowClass();
            splash.ShowDialog();

            SetCustomUI();
            //
            pufClass.PqcG3API_FA500InitObject();
            ictk_puf_api.Obj._FA500_WBM_InitVerifyDelegate(Delegate_Work);
            if (string.Compare( utils.get_conf(DefineString.SUPPORT_SSH, DefineString.APP_DEFAULT_CONF), "YES") == 0 )
            {
                g_bSupportssh = true;
            }
            else { g_bSupportssh = false; }

            if (g_bSupportssh == true)
            {
                TcpServer = new TcpServerSockClass(this);
                TcpServer.ServerStart();
            }

            if (pufClass.ispufconnected() == false)            {
            }
            else            {

                
            }

            AuthInfoTooltip.Opened += new RoutedEventHandler(whenToolTipOpens);
            IPAddress iPAddress = IPAddress.Any;
            string strListenPort = utils.get_conf(DefineString.HTTP_LISTENER_PORT, DefineString.HTTP_LISTENER_CONF);

            //DoNetshStuff("1234");
           // WebServer = new WebServerSockClass(IPAddress.Any, Convert.ToInt32(strListenPort), this);
            httpServer = new HttpServerClass(IPAddress.Any, Convert.ToInt32(strListenPort), this);
            //SslServer = new SslServerClass(IPAddress.Any, Convert.ToInt32("8082"), this, "server.pfx", "");
#endif
            Loaded += Window_Loaded;
        }

        public void whenToolTipOpens(object sender, RoutedEventArgs e)
        {
            string szNowPufUid = string.Empty;
            Auth_ToolTip_Title.Content = "Last Login information";
            pufClass.puf_wakeup();
            ictk_puf_api.chipinit();
            if (pufClass.ispufconnected() == true)
            {
                szNowPufUid = getstring_sn_number();
            }
            else
            {
                szNowPufUid = "Not Connected.";
            }
              
            nowuid_textblock.Text = "SN : " + szNowPufUid;

            uid_textblock.Text = "SN : " + g_strLastLoginPufUID;
            userid_textblock.Text = "Account : " + g_strLastLoginUserID;

            //MessageBox.Show("Test message2");
        }

        public void ToolTipOpen(object obj)
        {
            MessageBox.Show("Test message");
        }
        public void Delegate_Work(int workType, int data)
        {
            if (workType == (int)FP_WORK_TYPE.INDEX_FP_WORK_ENROLL)
            {
                if (INowWorkWindowType == (int)(WORK_WINDOW_TYPE.INDEX_WORK_SIGNUP))
                {
                    if (g_current_signup_Window == null)                    {
                        return;
                    }

                    Dispatcher.Invoke(DispatcherPriority.Normal, new Action(delegate
                    {
                        g_current_signup_Window.OnEnrollEvent(0, data);
                    }));
                }
            }
            else if (workType == (int)FP_WORK_TYPE.INDEX_FP_WORK_VERIFY)
            {
                switch(INowWorkWindowType )
                {
                    case (int)(WORK_WINDOW_TYPE.INDEX_WORK_SIGNIN):
                        {
                            if (g_current_mfa == null)  {
                                return;
                            }

                            if (data == (int)FP_WORK_RESULT.INDEX_FP_WORK_SUCCESS)
                            {
                                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(delegate
                                {
                                    g_current_mfa.UpdateImage(1);
                                }));
                            }
                            else 
                            {
                                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(delegate
                                {
                                    g_current_mfa.UpdateImage(0);
                                }));
                            }
                        }
                        break;
                    case (int)(WORK_WINDOW_TYPE.INDEX_WORK_RESIGNUP):
                        {
                            if (g_current_re_signup_Window == null)
                            {
                            }
                        }
                        break;
                    
                    case (int)(WORK_WINDOW_TYPE.INDEX_WORK_SIGNOUT):
                        {
                            if (g_current_signout_Window == null)
                            {
                                return;
                            }

                            if (data == (int)FP_WORK_RESULT.INDEX_FP_WORK_SUCCESS)
                            {
                                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(delegate
                                {
                                    g_current_signout_Window.UpdateImage(1);
                                }));
                            }
                            else 
                            {
                                Dispatcher.Invoke(DispatcherPriority.Normal, new Action(delegate
                                {
                                    g_current_signout_Window.UpdateImage(0);
                                }));
                            }
                        }
                        break;
                    default:
                        break;

                }
            }
        }

        static void DoNetshStuff(string sHttpPort)
        {
            // get full path to netsh.exe command
            string sPath = string.Empty;
            sPath = "http add urlacl url=http://+:" + sHttpPort + "/ user=Everyone listen=yes";
            
            var netsh = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "netsh.exe");

            
            
            // prepare to launch netsh.exe process
            var startInfo = new ProcessStartInfo(netsh);
            startInfo.Arguments = sPath;
            startInfo.UseShellExecute = true;
            startInfo.Verb = "runas";

            try
            {
                var process = Process.Start(startInfo);
                process.WaitForExit();
            }
            catch (FileNotFoundException)
            {
                // netsh.exe was missing?
            }
            catch (Win32Exception)
            {
                // user may have aborted the action, or doesn't have access
            }
            
        }

        private ImageSource second_imageLoad(string subpath)
        {
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.UriSource = new Uri(Environment.CurrentDirectory + subpath, UriKind.Relative);
            bi.EndInit();

            return bi;
        }

        private void SetCustomUI()
        {
            string strVenderNm = string.Empty;//
            string strBackImagePath = string.Empty;
            string strLogoImagePath = string.Empty;
            string strSloganMsg = string.Empty;

            ImageBrush myBrush = new ImageBrush();
            ImageBrush LogoBrush = new ImageBrush();
            Image image = new Image();
            Image logoimage = new Image();

            if (string.Compare(utils.get_conf(DefineString.USE_CUSTOM, DefineString.CUSTOM_CONF), DefineString.YES) == 0)
            {
                strVenderNm = utils.get_conf(DefineString.VENDERNAME, DefineString.CUSTOM_CONF);

                strBackImagePath = Environment.CurrentDirectory + "/res/custom/" + strVenderNm + "/" + "backimage.png";
                strLogoImagePath = "/res/custom/" + strVenderNm + "/" + "logo.png";
                strSloganMsg = utils.get_conf( DefineString.VENDER_SLOGANMSG, DefineString.CUSTOM_CONF);
            }
            else
            {
                strBackImagePath = Environment.CurrentDirectory + "/res/" + "backimage.png";
                strLogoImagePath = "/res/" + "logo.png";
                strSloganMsg = "Powered by PUF";
            }

            image.Source = new BitmapImage(
            new Uri(strBackImagePath, UriKind.Relative));
            myBrush.ImageSource = image.Source;
            main_border.Background = myBrush;

            ImageSource imgSource = new BitmapImage(new Uri(strLogoImagePath, UriKind.Relative));

            main_logo.Source = second_imageLoad(strLogoImagePath);
            main_vender_slogan.Text = strSloganMsg;
        }

        Mutex mutex = null;
        private void Duplicate_execution(string mutexName)
        {
            try
            {
                mutex = new Mutex(false, mutexName);
            }
            catch {
                g_bExitApp = true;
                this.Close();
            }
            if (mutex.WaitOne(0, false))
            {
                InitializeComponent();
            }
            else
            {
                g_bExitApp = true;
                this.Close();
            }
        }

        public void ExcuteWebLogViewofSSH_V2(TcpClient tcpClient)
        {
            g_SshClientSocket = tcpClient;

            string strUri = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.APP_DEFAULT_CONF);
            if (!string.IsNullOrEmpty(strUri))
            {
                Process process =  System.Diagnostics.Process.Start(strUri);
            }
        }

        public void ShowWaitingWindow()
        {
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(delegate
            {
                if (wating != null)
                    wating.Show();
                else
                {
                    wating = new WaitingWindow();
                    wating.Show();
                }
            }));
        }

        public void CloseWaitingWindow()
        {
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(delegate
            {
                if (wating != null)
                {
                    wating.Close();
                    wating = null;
                }
            }));
        }

        public void ExcuteWebLogViewofSSH(TcpClient client)
        {
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(delegate
            {
                if (webLobinView == null)
                {
                    webLobinView = new WebViewWindow(client, this);
                }
                webLobinView.ShowInTaskbar = true;
                webLobinView.Visibility = Visibility.Visible;
                webLobinView.WindowState = WindowState.Normal;
                webLobinView.Topmost = true;
                webLobinView.ShowDialog();

                if (webLobinView.DialogResult.HasValue && webLobinView.DialogResult.Value)
                {
                    MFA_FP_Window LoginDlg = new MFA_FP_Window(pufwarpper);

                    g_current_mfa = LoginDlg;
                    INowWorkWindowType = (int)WORK_WINDOW_TYPE.INDEX_WORK_SIGNIN;
                    g_bExistNowMfaWork = true;
                    
                    LoginDlg.ShowInTaskbar = true;
                    LoginDlg.Visibility = Visibility.Visible;
                    LoginDlg.WindowState = WindowState.Normal;
                    LoginDlg.Topmost = true;
                    string serverResult = "";
                    LoginDlg.ShowDialog();

                    if (LoginDlg.DialogResult.HasValue && LoginDlg.DialogResult.Value)
                    {
                        serverResult = "SUCCEED";
                        g_bIsSignin = true;
                    }
                    else
                    {
                        serverResult = "FAIL";
                        g_bIsSignin = false;
                    }

                    g_current_mfa = null;
                    g_bExistNowMfaWork = false;

                    NetworkStream stream = client.GetStream();

                    byte[] serverMsgAsByteArray = Encoding.UTF8.GetBytes(serverResult);
                    stream.Write(serverMsgAsByteArray, 0, serverMsgAsByteArray.Length);
                }

                webLobinView = null;
                client.Close();
            }));
        }

        public void ExcuteWebLogViewofWebAdmin_v2()
        {
            g_SshClientSocket = null;

            string strUri = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.KMS_ADMIN_WEB_CONF);
            if (!string.IsNullOrEmpty(strUri))
            {
                Process process = new Process();
                process.StartInfo.UseShellExecute = true;
                process.EnableRaisingEvents = true;
                process.StartInfo.FileName = "chrome";
                process.StartInfo.Arguments = strUri + " --new-window";
                process.Exited += proc_Exited;
                process.Start();
            }
        }

        static void proc_Exited(object sender, EventArgs e)
        {
        }

        public static string GetChromePath()
        {
            string lPath = null;
            try
            {
                var lTmp = Registry.GetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe", "", null);
                if (lTmp != null)
                    lPath = lTmp.ToString();
                else
                {
                    lTmp = Registry.GetValue(@"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe", "", null);
                    if (lTmp != null)
                        lPath = lTmp.ToString();
                }
            }
            catch {
                //Logger.Error(lEx);
            }

            if (lPath == null)
            {
                lPath = @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";
            }

            return lPath;
        }

        /// <summary>
        /// 메모장 끝나기리를 기다리는 메서드
        /// </summary>
        /// <returns></returns>
        private static int RunWaitNotePadExe()
        {
            // 메모장 실행 경로 입력
            var path = @"%systemRoot%\system32\notepad.exe";
            var fullPath = Environment.ExpandEnvironmentVariables(path);

            using (var process = Process.Start(fullPath))
            {
                if (process.WaitForExit(10000)) // 밀리초 단위
                {
                    return process.ExitCode;
                }

                throw new TimeoutException();
            }
        }

        public void ExcuteWebLogViewofWebAdmin()
        {
            g_SshClientSocket = null;
            Dispatcher.Invoke(DispatcherPriority.Normal, new Action(delegate
            {
                if (webLobinView == null)
                {
                    webLobinView = new WebViewWindow(this);
                }
                webLobinView.ShowInTaskbar = true;
                webLobinView.Visibility = Visibility.Visible;
                webLobinView.WindowState = WindowState.Normal;
                webLobinView.Topmost = true;
                webLobinView.ShowDialog();
                
#if _NOTUSE_WFPBROWSER
                if (webLobinView.DialogResult.HasValue && webLobinView.DialogResult.Value)
                {
                    MFA_FP_Window LoginDlg = new MFA_FP_Window(pufwarpper);

                    g_current_mfa = LoginDlg;
                    g_bExistNowMfaWork = true;

                    LoginDlg.ShowInTaskbar = true;
                    LoginDlg.Visibility = Visibility.Visible;
                    LoginDlg.WindowState = WindowState.Normal;
                    LoginDlg.Topmost = true;
                    LoginDlg.ShowDialog();

                    if (LoginDlg.DialogResult.HasValue && LoginDlg.DialogResult.Value)
                    {
                        bRet = true;
                    }
                    else
                    {
                        bRet = false;
                    }

                    if (bRet == true)
                    {
                        System.Diagnostics.Process.Start("https://www.naver.com/");
                    }

                    g_current_mfa = null;
                    g_bExistNowMfaWork = false;

                }

                webLobinView = null;
#endif
            }));
        }
        public void WebLogViewClose()
        {
            if (webLobinView == null)
            {
                return;
            }
            else
            {
                webLobinView.Close();
                webLobinView = null;
            }
        }


        const int NumTopTabs = 10;

        List<int> Counts = new List<int>();
        public ArrayList AllTabsUsed = new ArrayList();
        Process[] List;
        public int Delay = 250;
        public string CurrentTab = "";
        public string[] TopUsedTabs = new string[NumTopTabs];

        public bool IsChromeOpened()
        {
            List = Process.GetProcessesByName("chrome");
            if (List.Count() == 0)
                return false;
            else
                return true;
        }

        public void MonitoringAdminPage()
        {
            g_bWebAdminPageWorking = true;
            MonitoringPid();
        }

        public async void MonitoringPid()
        {
            bool bFinTarget = await MonitoringWork();
            if (bFinTarget == true)
            {
                MessageBox.Show("Manager page is down..");
            }
        }

        public Task<bool> MonitoringWork()
        {
            return Task.Factory.StartNew(() => WorkFunc());
        }

        public bool WorkFunc()
        {
            bool bExist = true, bChk = false;

            while (bExist)
            {
                bChk = chk_webadminpage();
                if (g_bWebAdminPageWorking == false || bChk == false)
                {
                    MessageBox.Show("closed admin page...... Send event to kms server ");
                    g_bWebAdminPageWorking = false;
                    return false;
                }
            }
            return true; 
        }

        public bool chk_webadminpage()
        {
            bool ret = false;
            Process[] chromeProcesses = Process.GetProcessesByName("chrome");
            List<uint> chromeProcessIds = chromeProcesses.Select(x => (uint)x.Id).ToList();
            List<IntPtr> windowHandles = new List<IntPtr>();

            EnumWindowsProc enumerateHandle = delegate (IntPtr hWnd, int lParam)
            {
                uint id;
                GetWindowThreadProcessId(hWnd, out id);

                // if the process we're enumerating over has an id in our chrome process ids, we need to inspect it to see if it is a window or other process
                if (chromeProcessIds.Contains(id))
                {
                    // get the name of the class of the window we are inspecting
                    var clsName = new StringBuilder(256);
                    var hasClass = GetClassName(hWnd, clsName, 256);
                    if (hasClass)
                    {
                        // get the text of the window we are inspecting
                        var maxLength = (int)GetWindowTextLength(hWnd);
                        var builder = new StringBuilder(maxLength + 1);
                        GetWindowText(hWnd, builder, (uint)builder.Capacity);

                        var text = builder.ToString();
                        var className = clsName.ToString();

                        // actual Google Chrome windows have text set to the title of the active tab
                        // in my testing, this needs to be coupled with the class name equaling "Chrome_WidgetWin_1". 
                        // i haven't tested this with other versions of Google Chrome
                        if (!string.IsNullOrWhiteSpace(text) && className.Equals("Chrome_WidgetWin_1", StringComparison.OrdinalIgnoreCase))
                        {
                            // if we satisfy the conditions, this is a Google Chrome window. Add the handle to the list of handles to use later.
                            windowHandles.Add(hWnd);
                        }
                    }
                }
                return true;
            };

            EnumDesktopWindows(IntPtr.Zero, enumerateHandle, 0);

            foreach (IntPtr ptr in windowHandles)
            {
                AutomationElement root = AutomationElement.FromHandle(ptr);
                System.Windows.Automation.Condition condTabItem = new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.TabItem);

                foreach (AutomationElement tabitem in root.FindAll(TreeScope.Descendants, condTabItem))
                {
                    //Console.WriteLine(tabitem.Current.Name);
                    if (tabitem.Current.Name.Contains(DefineString.WEB_PAGE_TITLE_ADMIN))
                    {
                        ret = true; break;
                    }
                }

                if (ret == true)
                {
                    break;
                }
            }

            return ret;
        }

        private string ByteToString(byte[] strByte)
        {
            string str = Encoding.Default.GetString(strByte);
            return str;
        }

        private async Task<byte[]?> collect_puf_cert()
        {
            byte[]? bytes = await Task.Run(() => pufwarpper.getbytecert_in_puf());
            if (bytes == null)
            {
                return null;
            }
            return bytes;
        }

        public async Task<byte[]?> collect_puf_prk()
        {
            ictk_puf_api.chipinit();

            bool bRet = ictk_puf_api.get_permission_of_puf();
            byte[] bytes2 = ictk_puf_api.g3berify_fingerprintf_of_puf();

            byte[]? bytes = await Task.Run(() => pufwarpper.getbyteprk_in_puf());
            if (bytes == null)
            {
                return null;
            }
            return bytes;
        }

        public byte[] sign_signature(string challenge, int ndataLen, byte[] puf_key)
        {
            byte[] out_data = new byte[3094];

            out_data = ictk_puf_api.pqc_wrapper_sign_signature(NeoHexString.HexStringToByteArray(challenge), NeoHexString.HexStringToByteArray(challenge).Length, puf_key);

            return out_data;
        }

        public bool process_pqc_kem_enc(byte[] cipher_text, byte[] share_key, byte[] public_key)
        {
            return ictk_puf_api.pqc_kem_enc(cipher_text, share_key, public_key);
        }

        public bool chk_puf_connected()
        {
            return pufClass.ispufconnected();
        }

        public string getstring_sn_number()
        {
            bool bRet = false;
            ictk_puf_api.chipinit();
            ictk_puf_api.chipwakeup();
            bRet = ictk_puf_api.get_permission_of_puf();
            string str = pufClass.get_puf_sn_for_string();

            return str;
        }

        public string get_hmac_signature(string type, string challenge)
        {
            ictk_puf_api.chipwakeup();
            ictk_puf_api.get_permission_of_puf();
            return pufwarpper.chk_hmac_sign_work(type,challenge);
        }

        public string getstring_pufrand(int nsize)
        {
            return pufwarpper.get_rand_string(nsize);
        }

        public string getstring_pufchallenge()
        {
            return pufwarpper.getstring_challenge_in_puf();
        }


        public byte[] get_puf_prk()
        {
            ictk_puf_api.chipinit();

            bool bRet = ictk_puf_api.get_permission_of_puf();
            byte[] bytes = ictk_puf_api.g3berify_fingerprintf_of_puf();
            var puf_crt = pufwarpper.getbytecert_in_puf();

            return puf_crt;
        }

        public bool get_agent_info(ref AGENT_INFO agent_info )
        {
            bool bRet = false;
            byte[] g_bytePUFCert = null;
            ictk_puf_api.chipinit();

            bRet = ictk_puf_api.get_permission_of_puf();

            byte[] bytes = ictk_puf_api.g3berify_fingerprintf_of_puf();

            var sn = ictk_puf_api.get_chip_serialnumber_for_byte();
            
            agent_info.uid = pufwarpper.get_serialnumber_string_in_puf();
            agent_info.pc_info = "";

            byte[] prk = pufwarpper.getbyteprk_in_puf();
            agent_info.crt = pufwarpper.getstringcert_in_puf();


            return bRet;
        }
        public bool Request_AdminPage_FingerPrintAuthentication_v2()
        {
            int ret = 0;
            bool bRet = false;

            if (pufClass.ispufconnected()  == false)
            {

                var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDRETRYMSG, MessageBoxButton.YesNo);
                while (messageBoxResult != MessageBoxResult.No) {

                    messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.OK);
                    if ((messageBoxResult == MessageBoxResult.OK) && (pufClass.ispufconnected() == true))
                    {
                        break;
                    }
                }

                if (pufClass.ispufconnected() == false)
                    return false;
            }

            MFA_FP_Window LoginDlg = new MFA_FP_Window(pufwarpper);

            g_current_mfa = LoginDlg;
            INowWorkWindowType = (int)WORK_WINDOW_TYPE.INDEX_WORK_SIGNIN;
            g_bExistNowMfaWork = true;

            LoginDlg.ShowInTaskbar = true;
            LoginDlg.Visibility = Visibility.Visible;
            LoginDlg.WindowState = WindowState.Normal;
            LoginDlg.Topmost = true;
            LoginDlg.ShowDialog();

            if (LoginDlg.DialogResult.HasValue && LoginDlg.DialogResult.Value)
            {
                bRet = true;
                g_bIsSignin = true;
            }
            else
            {
                bRet = false;
                g_bIsSignin = false;
            }

            g_current_mfa = null;
            g_bExistNowMfaWork = false;

            return bRet;
        }

        public void Request_AdminPage_FingerPrintAuthentication()
        {
            webLobinView.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
            {
                webLobinView.SuccessExit();
            }));
        }

        public bool Request_SSH_FingerPrintAuthentication_v2()
        {
            if (g_SshClientSocket  == null)
            {
                return false;
            }

            bool bRet = false;
         
            MFA_FP_Window LoginDlg = new MFA_FP_Window(pufwarpper);
            g_current_mfa = LoginDlg;
            INowWorkWindowType = (int)WORK_WINDOW_TYPE.INDEX_WORK_SIGNIN;
            g_bExistNowMfaWork = true;

            LoginDlg.ShowInTaskbar = true;
            LoginDlg.Visibility = Visibility.Visible;
            LoginDlg.WindowState = WindowState.Normal;
            LoginDlg.Topmost = true;
            string serverResult = "";
            LoginDlg.ShowDialog();

            if (LoginDlg.DialogResult.HasValue && LoginDlg.DialogResult.Value)
            {
                serverResult = "SUCCEED";
                bRet = true;
            }
            else
            {
                serverResult = "FAIL";
                bRet = false;
            }

            g_current_mfa = null;
            g_bExistNowMfaWork = false;

            NetworkStream stream = g_SshClientSocket.GetStream();

            byte[] serverMsgAsByteArray = Encoding.UTF8.GetBytes(serverResult);
            stream.Write(serverMsgAsByteArray, 0, serverMsgAsByteArray.Length);

            g_SshClientSocket = null;

            return bRet;
        }

        public void Request_SSH_FingerPrintAuthentication()
        {
            webLobinView.Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
            {
                webLobinView.SuccessExit();
            }));
        }

        public bool RequestFingerPrint_reRegistration()
        {
            bool bRet;
            if (pufClass.ispufconnected() == false)
            {

                var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.YesNo);
                while (messageBoxResult != MessageBoxResult.No)
                {

                    messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.YesNo);
                    if ((messageBoxResult == MessageBoxResult.Yes) && (pufClass.ispufconnected() == true))
                    {
                        break;
                    }
                }

                if (pufClass.ispufconnected() == false)
                    return false;
            }

            Mfa_work_re_registration_window re_regDlg = new Mfa_work_re_registration_window(pufwarpper);

            g_current_re_signup_Window = re_regDlg;
            INowWorkWindowType = (int)WORK_WINDOW_TYPE.INDEX_WORK_RESIGNUP;


            re_regDlg.ShowInTaskbar = true;
            re_regDlg.Visibility = Visibility.Visible;
            re_regDlg.WindowState = WindowState.Normal;
            re_regDlg.Topmost = true;
            re_regDlg.ShowDialog();

            if (re_regDlg.DialogResult.HasValue && re_regDlg.DialogResult.Value)
            {
                bRet = true;
            }
            else
            {
                bRet = false;
            }
            g_current_re_signup_Window = null;

            return bRet;
        }

        public void RequestFingerPrint_signout_puf()
        {
            bool bRet;
            if (pufClass.ispufconnected() == false)
            {
                var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.YesNo);
                while (messageBoxResult != MessageBoxResult.No)
                {

                    messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.YesNo);
                    if ((messageBoxResult == MessageBoxResult.Yes) && (pufClass.ispufconnected() == true))
                    {
                        break;
                    }
                }

                if (pufClass.ispufconnected() == false)
                    return;
            }

            Mfa_worksignout_window signoutDlg = new Mfa_worksignout_window(pufwarpper);

            g_current_signout_Window = signoutDlg;
            INowWorkWindowType = (int)WORK_WINDOW_TYPE.INDEX_WORK_SIGNOUT;

            signoutDlg.ShowInTaskbar = true;
            signoutDlg.Visibility = Visibility.Visible;
            signoutDlg.WindowState = WindowState.Normal;
            signoutDlg.Topmost = true;
            signoutDlg.ShowDialog();

            if (signoutDlg.DialogResult.HasValue && signoutDlg.DialogResult.Value)
            {
                var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_APP_TITLE_WARNING, Localization.res.STR_SIGNOUT_WARN_MSG, MessageBoxButton.YesNo);
                if (messageBoxResult != MessageBoxResult.No)
                {
                    //pufClass.puf_g3_set();
                    string challenge = pufClass.get_challenge_in_puf();
                    pufClass.puf_wakeup();
                    bRet = pufClass.remove_fingerprint_template_in_puf();
                    if (bRet == true)
                    {
                        pufClass.puf_wakeup();
                        string sign =  string.Empty;
                        bRet = pufClass.chip_reset_puf(STA_HaxString.HexStringToByteArray(challenge), STA_HaxString.HexStringToByteArray(sign));
                        if (bRet == true)
                        {

                        }
                        else
                        {

                        }
                        messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_SIGNOUT_TITLE, Localization.res.STR_MFA_RESETRESULTHELPMSG, MessageBoxButton.OK);
                        bRet = true;
                    }
                    else
                    {
                        bRet = false;
                    }
                }
            }
            else
            {
                bRet = false;
            }

            g_current_signout_Window = null;
        }

        public bool RegSecondWork()
        {
            bool bRet = false;
            ictk_puf_api.get_permission_of_puf();
            bRet = ictk_puf_api.macverify_fingerprintf_of_puf();
            byte[] bytes = ictk_puf_api.g3berify_fingerprintf_of_puf();

            return bRet;
        }

        public bool RequestFingerPrintRegistration()
        {
            bool bRet = false;
            if (pufClass.ispufconnected() == false)
            {

                var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.YesNo);
                while (messageBoxResult != MessageBoxResult.No)
                {

                    messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.YesNo);
                    if ((messageBoxResult == MessageBoxResult.Yes) && (pufClass.ispufconnected() == true))
                    {
                        break;
                    }
                }

                if (pufClass.ispufconnected() == false)
                    return false;
            }

            Mfa_workregistration_window regDlg = new Mfa_workregistration_window(pufwarpper, ictk_puf_api);

            g_current_signup_Window = regDlg;
            INowWorkWindowType = (int)WORK_WINDOW_TYPE.INDEX_WORK_SIGNUP;

            regDlg.ShowInTaskbar = true;
            regDlg.Visibility = Visibility.Visible;
            regDlg.WindowState = WindowState.Normal;
            regDlg.Topmost = true;
            regDlg.ShowDialog();

            if (regDlg.DialogResult.HasValue && regDlg.DialogResult.Value)
            {
                bRet = true;
            }
            else
            {
                bRet = false;
            }

            //bool bRet = false;
            ictk_puf_api.get_permission_of_puf();
            bRet = ictk_puf_api.macverify_fingerprintf_of_puf();
            byte[] bytes = ictk_puf_api.g3berify_fingerprintf_of_puf();

            g_current_signup_Window = null;

            return bRet;

        }

        public void RequestFingerPrint_logoff()
        {
            g_bIsSignin = false;
            MessageBox.Show("admin page logoff");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                int nMenuItemCnt = 0;
                _trayIcon = new System.Windows.Forms.NotifyIcon();
                
                _trayIcon.Click += delegate (object click, EventArgs eClick)
                {
                    OpenApplication();
                };


                System.Windows.Forms.ContextMenu AppTrayMenu = new System.Windows.Forms.ContextMenu();    
                System.Windows.Forms.MenuItem itemAppOpen = new System.Windows.Forms.MenuItem();   
                itemAppOpen.Index = nMenuItemCnt;
                itemAppOpen.Text = Properties.Resources.STR_MENU_OPEN;
                

                itemAppOpen.Click += delegate (object click, EventArgs eClick)    
                {
                    OpenApplication();
                };

                System.Windows.Forms.MenuItem itemSettingApplication = new System.Windows.Forms.MenuItem();
                itemSettingApplication.Index = nMenuItemCnt++;
                itemSettingApplication.Text = Properties.Resources.STR_MENU_SETTING;


                itemSettingApplication.Click += delegate (object click, EventArgs eClick)
                {
                    SettingApplication();
                };

                System.Windows.Forms.MenuItem itemAppInformation = new System.Windows.Forms.MenuItem(); 
                itemAppInformation.Index = nMenuItemCnt ++;
                itemAppInformation.Text = Properties.Resources.STR_MENU_INFO; 

                itemAppInformation.Click += delegate (object click, EventArgs eClick) 
                {
                    OpenInformation();
                };

                System.Windows.Forms.MenuItem itemAppExit = new System.Windows.Forms.MenuItem();    
                itemAppExit.Index = nMenuItemCnt ++;
                itemAppExit.Text = Properties.Resources.STR_MENU_EXIT;    

                itemAppExit.Click += delegate (object click, EventArgs eClick)    
                {
                    ExitApplication();
                };

                AppTrayMenu.MenuItems.Add(itemAppOpen);
                AppTrayMenu.MenuItems.Add(itemSettingApplication);
                AppTrayMenu.MenuItems.Add(itemAppExit);

                _trayIcon.Icon = Properties.Resources.ICTK;
                _trayIcon.Visible = true;

                _trayIcon.DoubleClick += delegate (object senders, EventArgs args)    
                {
                    DoubleMethod();
                };

                _trayIcon.ContextMenu   = AppTrayMenu;
                _trayIcon.Text          = Properties.Resources.STR_PRODUCT_NAME;
                _trayIcon.MouseDown     += NotifyIcon_MouseDown;
            }
            catch
            {

            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void NotifyIcon_MouseDown(object sender, System.Windows.Forms.MouseEventArgs e)
        {
            if (e.Button == System.Windows.Forms.MouseButtons.Right)
            {
            }
        }

        /// <summary>
        /// 
        /// </summary>
        private void DoubleMethod()
        {
            this.Show();
            this.WindowState = WindowState.Normal;
        }

        /// <summary>
        /// 
        /// </summary>
        private void Method2()
        {
            MessageBox.Show("select method2");
        }

        private void OpenInformation()
        {
            this.Close();
            InformationWindowClass informationWindowClass = new InformationWindowClass(this);
            informationWindowClass.Show();
        }

        /// <summary>
        /// 
        /// </summary>
        private void OpenApplication()
        {
            this.Show();
            this.WindowState = WindowState.Normal;
        }

        private void SettingApplication()
        {
            this.Close();

            if (g_bSupportssh == true)
            {
                AppSettingWindow appSettingWindow = new AppSettingWindow(this);
                appSettingWindow.Show();
                
            }
            else
            {
                AppSettingWindow_notsupport_ssh appSettingWindow = new AppSettingWindow_notsupport_ssh(this);
                appSettingWindow.Show();
                
            }
        }

        /// <summary>
        /// 
        /// </summary>
        private void ExitApplication()
        {
            g_bExitApp = true;
            _trayIcon.Dispose();
            this.Close();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="e"></param>
        protected override void OnStateChanged(EventArgs e)
        {
            if (WindowState.Minimized.Equals(WindowState))
            {
                this.Hide();
            }

            base.OnStateChanged(e);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="e"></param>
        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            if (g_bExitApp == true)
            {
                e.Cancel = false;
                base.OnClosing(e);
            }
            else
            {
                e.Cancel = true;
                this.Hide();
                base.OnClosing(e);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {

            this.Hide();
            e.Cancel = true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                DragMove();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnMinimize_Click(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btnSignin_Click(object sender, RoutedEventArgs e)
        {
            if (pufClass.ispufconnected() == false)
            {
                var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.OK);
            }
            else
            {
                this.Close();
                ExcuteWebLogViewofWebAdmin_v2();
            }
        }

        private void btnSaveLastLoginInfo_Click(object sender, RoutedEventArgs e)
        {
            var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MSG_SAVELASTLOGININFO, MessageBoxButton.YesNo);
            if (messageBoxResult == MessageBoxResult.Yes)
            {

            }
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            HwndSource source = PresentationSource.FromVisual(this) as HwndSource;
            source.AddHook(WndProc);
        }

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WM_COPYDATA)
            {
            }

            return IntPtr.Zero;
        }

        private void SettingBtn_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
            
            if (g_bSupportssh == true)
            {
                AppSettingWindow appSettingWindow = new AppSettingWindow(this);
                appSettingWindow.Show();
            }
            else
            {
                AppSettingWindow_notsupport_ssh appSettingWindow = new AppSettingWindow_notsupport_ssh(this);
                appSettingWindow.Show();
            }
        }

        private void InformationBtn_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
            InformationWindowClass informationWindowClass = new InformationWindowClass(this);
            informationWindowClass.Show();
        }

        private void btnAdminPage_Click(object sender, RoutedEventArgs e)
        {
            string strUri = "";
            strUri = "C:/loginsuccess.html";
            Process process = new Process();
            process.StartInfo.UseShellExecute = true;
            process.EnableRaisingEvents = true;
            process.StartInfo.FileName = "chrome";
            process.StartInfo.Arguments = strUri + " --new-window";
            process.Exited += proc_Exited;
            process.Start();
        }

#if _NOTUSE_CLASS

        private void ListenRequests()
        {
            Socket clientsocket = null;
            StreamReader reader = null;
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
                                    int num = 999;
                                    string serverMsg = string.Format("RECV=[username:{0}, ipaddress: {1}], SEND=[{2}]", split_data[0], split_data[1], serverResult);
                                    
                                    MFA_FP_Window LoginDlg = new MFA_FP_Window();
                                    LoginDlg.ShowInTaskbar = true;
                                    LoginDlg.Visibility = Visibility.Visible;
                                    LoginDlg.WindowState = WindowState.Normal;
                                    LoginDlg.Topmost = true;
                                    LoginDlg.ShowDialog   ();

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
                                }
                            }
                            catch (Exception e)
                            {
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
#endif // NOTUSECLASS
    }
}
