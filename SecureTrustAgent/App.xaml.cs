using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace SecureTrustAgent
{
    
    /// <summary>
    /// App.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class App : Application
    {
        private const int MINIMUM_SPLASH_TIME = 1500; // Miliseconds
        Mutex mutex = null;
        public App()
        {
            string applicationName = Process.GetCurrentProcess().ProcessName;
            Duplicate_execution(applicationName);

            
        }

        private void Duplicate_execution(string mutexName)
        {
            /*
            try
            {
                mutex = new Mutex(false, mutexName);
            }
            catch {
                Application.Current.Shutdown();
            }
            if (mutex.WaitOne(0, false))
            {
                InitializeComponent();
            }
            else
            {
                string strTitle = "";
                string strMessage = "";
                strTitle = Localization.res.STR_APP_TITLE_WARNING;
                strMessage = Localization.res.STR_APP_STARTFAIL_MESSAGE;

                var messageBoxResult = CustomMessageBoxClass.Show(strTitle, strMessage, MessageBoxButton.OK);

                Application.Current.Shutdown();
            }
            */
            InitializeComponent();
        }
        
        protected override void OnStartup(StartupEventArgs e)
        {
            
            
            /*
            // Step 2 - Start a stop watch  
            Stopwatch timer = new Stopwatch();
            timer.Start();

            // Step 3 - Load your windows but don't show it yet  
            base.OnStartup(e);
        //    MainWindow main = new MainWindow();
            timer.Stop();

            int remainingTimeToShowSplash = MINIMUM_SPLASH_TIME - (int)timer.ElapsedMilliseconds;
            if (remainingTimeToShowSplash > 0)
                Thread.Sleep(remainingTimeToShowSplash);

            splash.Close();
            */
        }
        
    }
}
