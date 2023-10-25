using CefSharp;
using CefSharp.Wpf;
using SecureTrustAgent.Helpers;
using SecureTrustAgent.TRANS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
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
    /// WebViewWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class WebViewWindow : Window
    {
        public delegate void EventHandler(object sender, EventArgs e);
        public event EventHandler myEvent;
        UtilsClass utils = new UtilsClass();
        TcpClient g_client;
        public string Url { get; set; }
        public string SendString { get; set; }

        MainWindow _mainWindow;

        public WebViewWindow(TcpClient new_socket, MainWindow main)
        {
            this._mainWindow = main;
            InitializeComponent();
            //this.Closed += new EventHandler(OnClosing);

            g_client = new_socket;
            ChromiumWebBrowser browser = new ChromiumWebBrowser();

            Cef.Initialize(new CefSettings());

            //webView.Source = new Uri("file:///c:/ws_test.html");
            webView.Source = new Uri("https://43.201.210.221/");
            //webView.Source = new Uri("file:///c:/ws_test.h");
            //webView.Source = new Uri(WWW.);
            /*
            this.DataContext = this;
            Microsoft.Web.WebView2.WinForms.WebView2 webView = new Microsoft.Web.WebView2.WinForms.WebView2();

            this.webview.Address = "c:/ws_test.html";
            //https://kr.ictk.com/What
            //this.webview.Source = new Uri("file:///c:/ws_test.html");
            //this.webview.Source = new Uri("https://kr.ictk.com/What");

            */
        }
        /*
        private void Browser_LoadingStateChanged(object sender, LoadingStateChangedEventArgs e)
        {
            if (!e.IsLoading)
            {
                if (!webview.CanExecuteJavascriptInMainFrame)
                    webview.Reload();
            }
        }

        private async void WebBrowserJavascriptCall(string script)
        {
            // 페이지가 로딩 된 후 자바스크립트 실행
            webview.FrameLoadEnd += async (sender, args) =>
            {
                // 브라우저 메인 프레임 객체 생성
                var frame = webview.GetMainFrame();

                // 3초 대기
                await Task.Delay(3000);

                // 자바스크립트 함수 실행
                var result = await frame.EvaluateScriptAsync(script);

                // 자바스크립트 실행 결과
                if (result.Success)
                {
                    // 성공 시 수행 코드
                }
                else
                {
                    // 실패 시 수행 코드
                }
            };
        }

        private void InitializeCefSharp()
        {
            // 크롬 브라우저 설정 초기화
            Cef.Initialize(new CefSettings());

            // 크롬 브라우저 크기 설정
            webview.Size = new Size(this.webview.Width, 300);
            webview.Location = new Point(0, 0);

            // 폼에 크롬 브라우저 추가
            this.Controls.Add(browser);

            // 웹 페이지 로드
            browser.LoadUrl("https://www.google.com");
        }
    }
        */


    public WebViewWindow(MainWindow main)
        {
            this._mainWindow = main;
            InitializeComponent();

            webView.Source = new Uri("file:///c:/ws_test.html");
            /*
            this.DataContext = this;
            Microsoft.Web.WebView2.WinForms.WebView2 webView = new Microsoft.Web.WebView2.WinForms.WebView2();

            this.webview.Address = "c:/ws_test.html";

            //this.webview.Source = new Uri("file:///c:/ws_test.html");
            //this.webview.Source = new Uri("https://kr.ictk.com/What");
            */
        }

        public TcpClient get_client_Socket()
        {
            return g_client;
        }

        public void EndWork()
        {
            this.DialogResult = true;
            this.Close();
        }

        public void eventTest()
        {
            if (myEvent != null)
            {
                myEvent(this, new EventArgs());
            }
        }

        public void SuccessExit()
        {
            this.DialogResult= true;
            this.Close();
        }

        public void ErrorExit()
        {
            this.DialogResult = false;
            //this.Close();
        }

        /*
        protected void OnCloed(object sender, EventArgs e)
        {
            
            // _mainWindow.WebLogViewClose();
            //this.DialogResult = true;
            
            base.OnClosed(e);
        }
        */

        private void Window_Activated(object sender, EventArgs e)
        {

        }
    }
}