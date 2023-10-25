//#define _SUPPORT_SSH
using SecureTrustAgent.Helpers;
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
using System.Windows.Shapes;

namespace SecureTrustAgent
{
    /// <summary>
    /// AppSettingWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class AppSettingWindow_notsupport_ssh : Window
    {
        /*
        bool g_bUseSetInit = false;
        */
        UtilsClass utils = new UtilsClass();
        MainWindow mainWindow;

        public string strHttpListenerPort = string.Empty,
            strKmsAdminPageUrl = string.Empty,
            strKmsAdminPagePort = string.Empty,
            strSupportSsh = string.Empty,

            strNowLang = string.Empty;

        /*
        public string strSSHPort = string.Empty,
#if (_SUPPORT_SSH)
            strSSHDefaultIPAddress = string.Empty, 
            strSSHUseAnyIP = string.Empty,
#endif
            strWEBPort = string.Empty, 
            strWEBDefaultIPAddress = string.Empty,
            strWEBUseAnyIP = string.Empty,
             strWebLoginPageUrl = string.Empty,
            strWebLoginpatePort = string.Empty,
            strNowLang = string.Empty;
        */
        string strLangNowSetValue = string.Empty;


        public AppSettingWindow_notsupport_ssh(MainWindow mainWindow)
        {
            InitializeComponent();
            editWebPort.IsEnabled = false;
            this.mainWindow = mainWindow;
            SetCustomUI();
            LoadAppConfig();
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

            ImageBrush myBrush = new ImageBrush();
            ImageBrush LogoBrush = new ImageBrush();
            Image image = new Image();
            Image logoimage = new Image();

            if (string.Compare(utils.get_conf(DefineString.USE_CUSTOM, DefineString.CUSTOM_CONF), DefineString.YES) == 0)
            {
                strVenderNm = utils.get_conf(DefineString.VENDERNAME, DefineString.CUSTOM_CONF);

                strBackImagePath = Environment.CurrentDirectory + "/res/custom/" + strVenderNm + "/" + "backimage.png";
                strLogoImagePath = "/res/custom/" + strVenderNm + "/" + "logo.png";
            }
            else
            {
                strBackImagePath = Environment.CurrentDirectory + "/res/" + "backimage.png";
                strLogoImagePath = "/res/" + "logo.png";
            }

            image.Source = new BitmapImage(
            new Uri(strBackImagePath, UriKind.Relative));
            myBrush.ImageSource = image.Source;
            setting_window_border_nonSSH.Background = myBrush;
            /*
            ImageSource imgSource = new BitmapImage(new Uri(strLogoImagePath, UriKind.Relative));

            main_logo.Source = second_imageLoad(strLogoImagePath);
            */

        }

        private void LoadAppConfig()
        {
            strHttpListenerPort = utils.get_conf(DefineString.HTTP_LISTENER_PORT, DefineString.HTTP_LISTENER_CONF);
            strKmsAdminPageUrl = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.KMS_ADMIN_WEB_CONF);
            strKmsAdminPagePort = utils.get_conf(DefineString.WEB_LOGIN_PAGEPORT, DefineString.KMS_ADMIN_WEB_CONF);
            strNowLang = utils.get_conf(DefineString.APP_LANGUAGE_STRING, DefineString.APP_LANGUAGE_SECTION);
            //strListenPort = utils.get_conf(DefineString.HTTP_LISTENER_PORT, DefineString.HTTP_LISTENER_CONF);

            editHttpListernPort.Text = strHttpListenerPort;
            editWebIpAddr.Text = strKmsAdminPageUrl;
            editWebPort.Text = strKmsAdminPagePort;

            for (int i = 0; i < langCombo.Items.Count; i++)
            {
                string tmp = langCombo.Items.GetItemAt(i).ToString();
                if (string.Compare(tmp, strNowLang) == 0)
                {
                    langCombo.SelectedIndex = i;
                    break;
                }
            }
            if (string.Compare("YES", utils.get_conf(DefineString.WEB_USER_ANYIP, DefineString.WEB_SECTION)) == 0)
            {
                //checkWebAny.IsChecked = true;
            }

#if _BACK_ORG
            strSSHPort = utils.get_conf(DefineString.SSH_LISTEN_PORT, DefineString.SSH_SECTION);
#if (_SUPPORT_SSH)
            strSSHDefaultIPAddress = utils.get_conf(DefineString.SSH_DEFAULT_IP, DefineString.SSH_SECTION);
#endif
            strWEBPort = utils.get_conf(DefineString.WEB_LISTEN_PORT, DefineString.WEB_SECTION);
            strWEBDefaultIPAddress = utils.get_conf(DefineString.WEB_DEFAULT_IP, DefineString.WEB_SECTION);
            strNowLang = utils.get_conf(DefineString.APP_LANGUAGE_STRING, DefineString.APP_LANGUAGE_SECTION);
            strWebLoginPageUrl = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.APP_DEFAULT_CONF);
            strWebLoginpatePort = utils.get_conf(DefineString.WEB_LOGIN_PAGEPORT, DefineString.APP_DEFAULT_CONF);
            /*
             */

            editWebIpAddr.Text = strWebLoginPageUrl;
            editWebPort.Text = strWebLoginpatePort;
#if (_SUPPORT_SSH)
            editSSHIpAddr.Text = strSSHDefaultIPAddress;
            editSSHPort.Text = strSSHPort;
#endif
            for (int i = 0; i <  langCombo.Items.Count; i++)
            {
                string tmp = langCombo.Items.GetItemAt(i).ToString();
                if (string.Compare(tmp, strNowLang) == 0)
                {
                    langCombo.SelectedIndex = i;
                    break;
                }
            }
            if (string.Compare("YES", utils.get_conf(DefineString.WEB_USER_ANYIP, DefineString.WEB_SECTION)) == 0)
            {
                checkWebAny.IsChecked = true;
            }
#if (_SUPPORT_SSH)
            if (string.Compare("YES", utils.get_conf(DefineString.SSH_USER_ANYIP, DefineString.SSH_SECTION)) == 0)
            {
                checkSshAny.IsChecked = true;
            }
#endif
#endif
        }

        private void SetUserInterfaceStr(int nLangTuye)
        {
            if (nLangTuye == 0) // default and Eng
            {
                tb_WebadminHelp.Text = Properties.Resources.STR_SET_WEBADMINHELP;
            }
        }

        private void btnMinimize_Click(object sender, RoutedEventArgs e)
        {

        }

        private void btnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void btnSettingSave_Click(object sender, RoutedEventArgs e)
        {
            bool bChkNeedUpdate = false;
            bool bChkNeedToRestart = false;
            string _strHttpListenerPort = editHttpListernPort.Text;
            string _strKmsAdminPageUrl = editWebIpAddr.Text;
            string _strKmsAdminPagePort = editWebPort.Text;
            string _strLang = langCombo.Text;

            string _BeforSaveLang = string.Empty;
            /*
                        strHttpListenerPort = utils.get_conf(DefineString.HTTP_LISTENER_PORT, DefineString.HTTP_LISTENER_CONF);
                        strKmsAdminPageUrl = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.KMS_ADMIN_WEB_CONF);
                        strKmsAdminPagePort = utils.get_conf(DefineString.WEB_LOGIN_PAGEPORT, DefineString.KMS_ADMIN_WEB_CONF);
                        
            */

            _BeforSaveLang = utils.get_conf(DefineString.APP_LANGUAGE_STRING, DefineString.APP_LANGUAGE_SECTION);

            if (string.Compare(strHttpListenerPort, _strHttpListenerPort) != 0)
            {
                bChkNeedUpdate = true;
            }
            if (string.Compare(_BeforSaveLang, _strLang) != 0)
            {
                bChkNeedUpdate = true;
            }

            utils.set_conf(DefineString.HTTP_LISTENER_PORT, _strHttpListenerPort, DefineString.HTTP_LISTENER_CONF);
            utils.set_conf(DefineString.WEB_LOGIN_PAGEURL, _strKmsAdminPageUrl, DefineString.KMS_ADMIN_WEB_CONF);
            utils.set_conf(DefineString.WEB_LOGIN_PAGEPORT, _strKmsAdminPagePort, DefineString.KMS_ADMIN_WEB_CONF);
            utils.set_conf(DefineString.APP_LANGUAGE_STRING, strLangNowSetValue, DefineString.APP_LANGUAGE_SECTION);

            if (bChkNeedUpdate == true)
            {
                Properties.Settings.Default.language = _strLang;
                Properties.Settings.Default.Save();

                System.Diagnostics.Process.Start(Application.ResourceAssembly.Location);
                Application.Current.Shutdown();
            }

#if _BAK_ORG
            bool bChkNeedUpdate = false;
            bool bChkNeedToRestart = false;
            string strWebIPNowSetValue = string.Empty;
            string strWebPortNowSetValue = string.Empty;
#if (_SUPPORT_SSH)
            string strSshIPNowSetValue = string.Empty;
            string strSshPortNowSetValue = string.Empty;
#endif
            string strWebUseAnyIPNowSetValue = string.Empty;
            string strSshUseAnyIPNowSetValue = string.Empty;

            // string strLangNowSetValue = string.Empty;

            strWebIPNowSetValue = editWebIpAddr.Text;
            strWebPortNowSetValue = editWebPort.Text;
#if (_SUPPORT_SSH)
            strSshIPNowSetValue = editSSHIpAddr.Text;
            strSshPortNowSetValue = editSSHPort.Text;
#endif
/*
if (checkWebAny.IsChecked == true)            {
    strWEBUseAnyIP = "YES";
}
else            {
    strWEBUseAnyIP = "NO";
}
*/
#if (_SUPPORT_SSH)
            if (checkSshAny.IsChecked == true)            {
                strSSHUseAnyIP = "YES";
            }
            else            {
                strSSHUseAnyIP = "NO";
            }
#endif

            if (string.Compare(strWEBDefaultIPAddress, strWebIPNowSetValue) != 0 ) {
                bChkNeedUpdate = true;
            }
            if (string.Compare(strWEBPort, strWebPortNowSetValue) != 0)            {
                bChkNeedUpdate = true;
            }

#if (_SUPPORT_SSH)
            if (string.Compare(strSSHDefaultIPAddress, strSshIPNowSetValue) != 0)  {
                bChkNeedUpdate = true;
            }
            if (string.Compare(strSSHPort, strSshPortNowSetValue) != 0)            {
                bChkNeedUpdate = true;
            }
#endif

            if (string.Compare(strHttpListenerPort, utils.get_conf(DefineString.HTTP_LISTENER_PORT, DefineString.HTTP_LISTENER_CONF)) != 0)         {
                bChkNeedUpdate = true;
            }
#if (_SUPPORT_SSH)
            if (string.Compare(strSSHUseAnyIP, utils.get_conf(DefineString.SSH_USER_ANYIP, DefineString.SSH_SECTION)) != 0)     {
                bChkNeedUpdate = true;
            }
#endif
            if (string.Compare(strNowLang, strLangNowSetValue) != 0)               {
                bChkNeedUpdate = true;
                bChkNeedToRestart = true;
            }

            if (bChkNeedUpdate == false)
            {
                return;
            }
            
            strWEBDefaultIPAddress = strWebIPNowSetValue;
            strWEBPort = strWebPortNowSetValue;
#if (_SUPPORT_SSH)
            strSSHDefaultIPAddress = strSshIPNowSetValue;
            strSSHPort = strSshPortNowSetValue;
#endif
            strNowLang = strLangNowSetValue;

            string strTitle = Localization.res.STR_SET_MAINTITLE;
            string strMessage = string.Empty;

            if (bChkNeedToRestart == true)
            {
                strMessage = Localization.res.STR_SET_LANGUAGE_WARNMSG;
            }
            else
            {
                strMessage = Localization.res.STR_SET_LANGUAGE_WARNMSG2;
            }

            var messageBoxResult = CustomMessageBoxClass.Show(strTitle, strMessage, MessageBoxButton.YesNo);
            if (messageBoxResult != MessageBoxResult.Yes) return;

            utils.set_conf(DefineString.WEB_DEFAULT_IP, strWEBDefaultIPAddress, DefineString.WEB_SECTION);
            utils.set_conf(DefineString.WEB_LISTEN_PORT, strWEBPort, DefineString.WEB_SECTION);
            utils.set_conf(DefineString.WEB_USER_ANYIP, strWEBUseAnyIP, DefineString.WEB_SECTION);
            utils.set_conf(DefineString.WEB_LOGIN_PAGEURL, strWebLoginPageUrl, DefineString.WEB_SECTION);
#if (_SUPPORT_SSH)
            utils.set_conf(DefineString.SSH_DEFAULT_IP, strSSHDefaultIPAddress, DefineString.SSH_SECTION);
            utils.set_conf(DefineString.SSH_LISTEN_PORT, strSSHPort, DefineString.SSH_SECTION);
            utils.set_conf(DefineString.SSH_USER_ANYIP, strSSHUseAnyIP, DefineString.SSH_SECTION);
#endif
            utils.set_conf(DefineString.APP_LANGUAGE_STRING, strLangNowSetValue, DefineString.APP_LANGUAGE_SECTION);
            if (bChkNeedToRestart == true)
            {
                Properties.Settings.Default.language = strNowLang;
                Properties.Settings.Default.Save();

                System.Diagnostics.Process.Start(Application.ResourceAssembly.Location);
                Application.Current.Shutdown();
            }   
            

#endif
        }
#if (_SUPPORT_SSH)
        private void SSHUserAnyIP_Checked(object sender, RoutedEventArgs e)
        {
            strSSHUseAnyIP = "YES";
        }

        private void SSHUserAnyIP_UnChecked(object sender, RoutedEventArgs e)
        {
            strSSHUseAnyIP = "NO";
        }
#endif
        private void WebUserAnyIP_Checked(object sender, RoutedEventArgs e)
        {
            //strWEBUseAnyIP = "YES";
        }

        private void WebUserAnyIP_UnChecked(object sender, RoutedEventArgs e)
        {
            //strWEBUseAnyIP = "NO";
        }

        private void Windows_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                DragMove();
        }

        private void cbLanguage_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            
        }

        private void langCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            strLangNowSetValue = (string)((System.Windows.Controls.ComboBox)sender).SelectedItem;
        }

        private void HomeBtn_Click(object sender, RoutedEventArgs e)
        {
            mainWindow.Show();
            mainWindow.WindowState = WindowState.Normal;

            this.Close();
        }
    }
}
