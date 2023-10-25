using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;
using SecureTrustAgent.Helpers;
using SecureTrustAgent.Localization;
using WpfAnimatedGif;

namespace SecureTrustAgent
{
    
    /// <summary>
    /// MFA_FP_Window.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class Mfa_work_re_registration_window : Window
    {
        int g_nCnt = 0;
        ictk_puf_warpper puf_obj;
        DispatcherTimer timer;
        public Mfa_work_re_registration_window(ictk_puf_warpper puf_Warpper)
        {
            puf_obj = puf_Warpper;
            InitializeComponent();
            Loaded += Window_Loaded;

            timer = new DispatcherTimer();
            timer.Interval = TimeSpan.FromMilliseconds(2000);    //시간간격 설정
            timer.Tick += new EventHandler(timer_Tick);          //이벤트 추가
            timer.Start();
        }

        private void MFA_FP_Window_Loaded(object sender, RoutedEventArgs e)
        {
            throw new NotImplementedException();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            string strProgressionnumber = string.Empty;
            strProgressionnumber += "( 0 / 5 )";
            work_cnt.Text = strProgressionnumber;
        }

        private void timer_Tick(object sender, EventArgs e)
        {
            if (g_nCnt == 0)
            {
                mfa_working();
            }
            else if (g_nCnt == 1)
            {
                regwin_subtitle.Text = Localization.res.STR_MFA_AUTHHELPSUBMESSAGE;
            }

            if (g_nCnt <= 5)
            {
                string strProgressionnumber = string.Empty;
                strProgressionnumber = string.Format("( {0} / 5 )", g_nCnt);// += "( 0 / 5 )";
                work_cnt.Text = strProgressionnumber;
            }
            if (g_nCnt == 7)
            {
                timer.Stop();
                this.Close();
            }

            g_nCnt++;
        }

        public async void mfa_working()
        {
            await verif_work();
        }

        public Task<bool> verif_work()
        {
            return Task.Factory.StartNew(() => puf_obj.proceed_fingerprintverif());
        }

        public void UpdateImage(int nType)
        {
            string strMessage = "";
            if (nType == 1)
            {
                strMessage = Localization.res.STR_MFA_SUCCESS_RESULTMSG_FIRST + Localization.res.STR_MFA_SUCCESS_RESULTMSG_SECEND; ;
                mfa_subtitle.Text = strMessage;
                
                this.DialogResult = true; 
                this.Close();
            }
            else
            {
                strMessage = Localization.res.STR_MFA_FAILMSG;

                var controller = ImageBehavior.GetAnimationController(this.work_animation);
                controller.Pause();

                var messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, strMessage, MessageBoxButton.YesNo);
                if (messageBoxResult != MessageBoxResult.Yes)
                {
                    this.DialogResult = false;
                    this.Close();
                }
                else
                {
                    if (puf_obj.isconnect_puf() == true)
                    {
                        mfa_working();
                        controller.Play();
                    }

                    else
                    {
                        messageBoxResult = CustomMessageBoxClass.Show(Localization.res.STR_MFA_FAILTITLE, Localization.res.STR_MFA_FAILANDFINMSG, MessageBoxButton.OK);
                        this.DialogResult = false;
                        this.Close();
                    }
                }
            }
        }

        private static DateTime Delay(int MS)
        {
            DateTime thisMoment = DateTime.Now;
            TimeSpan duration = new TimeSpan(0,0,0,0,MS);
            DateTime afterMoment = thisMoment.Add(duration);

            while (afterMoment >= thisMoment)
            {
                if (System.Windows.Application.Current != null)
                {
                    System.Windows.Application.Current.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Background, new Action(delegate { }));
                }

                thisMoment = DateTime.Now;
            }

            return DateTime.Now;
        }

        async private void timeDelay(int tDelaySecond)
        {
            await Task.Delay(tDelaySecond);
        }
#if _USE_FINGERPRINT_IMAGE
        private ImageSource static_imageLoad()
        {
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.UriSource = new Uri(Environment.CurrentDirectory + "/" + "static_fingerprint.png", UriKind.Relative);
            bi.EndInit();

            return bi;
        }

        private ImageSource first_imageLoad()
        {
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.UriSource = new Uri(Environment.CurrentDirectory + "/" + "636005-1.png", UriKind.Relative);
            bi.EndInit();

            return bi;
        }

        private ImageSource second_imageLoad()
        {
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.UriSource = new Uri(Environment.CurrentDirectory + "/" + "636005-2.png", UriKind.Relative);
            bi.EndInit();

            return bi;
        }

        private ImageSource third_imageLoad()
        {
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.UriSource = new Uri(Environment.CurrentDirectory + "/" + "636005-3.png", UriKind.Relative);
            bi.EndInit();

            return bi;
        }

        private ImageSource forth_imageLoad()
        {
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.UriSource = new Uri(Environment.CurrentDirectory + "/" + "636005-4.png", UriKind.Relative);
            bi.EndInit();

            return bi;
        }

        private ImageSource success_imageLoad()
        {
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.UriSource = new Uri(Environment.CurrentDirectory + "/" + "Success.png", UriKind.Relative);
            bi.EndInit();
            
            return bi;
        }

        private ImageSource fail_imageLoad()
        {
            var bi = new BitmapImage();
            bi.BeginInit();
            bi.CacheOption = BitmapCacheOption.OnLoad;
            bi.UriSource = new Uri(Environment.CurrentDirectory + "/" + "failed.png", UriKind.Relative);
            bi.EndInit();
            
            return bi;
        }
#endif

        private void btnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void btnMinimize_Click(object sender, RoutedEventArgs e)
        {
        }

        private void Window_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if(e.LeftButton == MouseButtonState.Pressed)
                DragMove();
        }

        private void Signin_Click(object sender, RoutedEventArgs e)
        {
#if _USE_SIGN_BUTTON
            string btnString = btSignin.Content.ToString();
            if (string.Compare(btnString, Localization.res.STR_MFA_CONTENT_CLOSE) == 0 )
            {
                this.DialogResult = true; ;
                this.Close();
            }
            else if (string.Compare(btnString, Localization.res.STR_MFA_CONTENT_RETRY) == 0 )
            {
                bool bret = false;
               // image.Source = static_imageLoad();
                //bret = puf_obj.proceed_fingerprintverif();
                mfa_working();

                var controller = ImageBehavior.GetAnimationController(this.work_animation);
                controller.Play();

                //mediaElement.Play();
            }
            else
            {
                this.DialogResult = true; ;
                this.Close();
            }
            /*
            string strMessage = string.Empty;
            bool bret = false;
            bret = puf_obj.proceed_fingerprintverif();
            

            if (bret == true)
            {
                strMessage = Localization.res.STR_RETSTR_SUCCESS_MFAAUTH;
            }else
            {
                strMessage = Localization.res.STR_RETSTR_FAIL_MFAAUTH;
            }

            CustomMessageBoxClass.Show("SN", strMessage, MessageBoxButton.OK);

            this.DialogResult = bret;
            */
            /*obj = new PqcFA500();

            string strTitle = "FingerPrint", strMessage = "";
            int cnt = obj._FA500_WBM_GetDeviceCount();
            ValueType retremain = 0;
            if (cnt > 0)
            {
                ValueType verifybuflen = 0;
                byte[] verifybuffer = new byte[4096];
                string devicename = obj._FA500_WBM_GetDeviceName(0);

                int bret = obj._FA500_WBM_G3_Enrolled(devicename);
                if (bret == (int)FP_WORK_RESULT.INDEX_FP_WORK_SUCCESS)
                {
                    ret = obj._FA500_WBM_FP_Verify(devicename, verifybuffer, ref verifybuflen);
                    if (ret < 0)
                    {

                        strMessage = "지문인증 실패";
                    }
                    else
                    {
                        strMessage = "지문인증 성공";
                    }

                    var messageBoxResult = CustomMessageBoxClass.Show(strTitle, strMessage, MessageBoxButton.OK);
                }
            }
            */
#endif
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

        private void Gif_Animation_MediaEnded(object sender, RoutedEventArgs e)
        {
        }
    }
}
