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
    /// InformationWindowClass.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class InformationWindowClass : Window
    {
        UtilsClass utils = new UtilsClass();
        MainWindow mainWindow;
        public InformationWindowClass(MainWindow mainWindow )
        {
            InitializeComponent();
            SetCustomUI();
            this.mainWindow = mainWindow;
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
            inform_window_border.Background = myBrush;
            /*
            ImageSource imgSource = new BitmapImage(new Uri(strLogoImagePath, UriKind.Relative));

            main_logo.Source = second_imageLoad(strLogoImagePath);
            */

        }


        private void Windows_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                DragMove();
        }

        private void btnMinimize_Click(object sender, RoutedEventArgs e)
        {

        }

        private void btnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void HomeBtn_Click(object sender, RoutedEventArgs e)
        {
            mainWindow.Show();
            mainWindow.WindowState = WindowState.Normal;

            this.Close();
        }
    }
}
