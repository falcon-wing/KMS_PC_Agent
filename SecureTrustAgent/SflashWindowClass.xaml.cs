using SecureTrustAgent.Helpers;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace SecureTrustAgent
{
    /// <summary>
    /// SflashWindowClass.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class SflashWindowClass : Window
    {
        int g_iprogresspos = 0;
        UtilsClass utils = new UtilsClass();
        BackgroundWorker _worker = null;
        private const int MINIMUM_SPLASH_TIME = 1500; // Miliseconds
        public SflashWindowClass()
        {
            InitializeComponent();
            SetCustomUI();
            /*
             * 
             */

            _worker = new BackgroundWorker();
            _worker.WorkerReportsProgress = true;
            _worker.DoWork += _worker_DoWork;
            _worker.ProgressChanged += _worker_ProgressChanged;
            _worker.RunWorkerCompleted += _worker_RunWorkerCompleted;
            _worker.RunWorkerAsync();
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

            if (string.Compare( utils.get_conf(DefineString.USE_CUSTOM, DefineString.CUSTOM_CONF), DefineString.YES) == 0 )
            {
                strVenderNm = utils.get_conf(DefineString.VENDERNAME, DefineString.CUSTOM_CONF);

                strBackImagePath = Environment.CurrentDirectory + "/res/custom/" + strVenderNm + "/" +"backimage.png";
                strLogoImagePath = "/res/custom/" + strVenderNm + "/" + "logo.png";
                strSloganMsg = utils.get_conf(DefineString.VENDER_SLOGANMSG, DefineString.CUSTOM_CONF);
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
            sf_main_border.Background = myBrush;

            ImageSource imgSource = new BitmapImage(new Uri(strLogoImagePath, UriKind.Relative));
            
            sf_logo_image.Source = second_imageLoad(strLogoImagePath);
            sf_vender_slogan.Text = strSloganMsg;
        }

        private void Windows_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                DragMove();
        }

        private void _worker_DoWork(object sender, DoWorkEventArgs e)
        {
            for (int i = 0; i < 100; i = i + 2)
            {
                _worker.ReportProgress(i);
                Thread.Sleep(100);
            }
        }

        private void _worker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            flashProgressBar.Value = e.ProgressPercentage;
        }

        private void _worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            flashProgressBar.Value = flashProgressBar.Maximum;
            Thread.Sleep(100);
            this.Close();
        }

        private void timer_Tick(object sender, EventArgs e)
        {
            Thread.Sleep(0);
            g_iprogresspos += 10;
            //flashProgressBar.SetValue()
            this.Close();
        }
    }
}
