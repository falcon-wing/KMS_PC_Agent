using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.RightsManagement;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace SecureTrustAgent.Helpers
{
    public enum LOGINFO
    {
        INFO,
        WARN,
        ERROR,
        FATAL
    }
    internal class LogClass
    {
        public string LogPath { get; set; }
        public string LogFilePath { get; set; }

        public bool GetEnvironment()
        {
            bool bChkStat = false;
            string strCurrentPath = string.Empty;
            if (LogFilePath == null || LogFilePath.Length <= 0)
            {
                if (String.IsNullOrEmpty(LogFilePath))
                {
                    strCurrentPath = System.IO.Directory.GetCurrentDirectory();
                    LogFilePath = strCurrentPath + "\\" + "Logs" + "\\PCAent.log";
                    
                    bChkStat = true;
                }
            }

            LogPath = strCurrentPath+ "\\" + "Logs";

            return true;
        }

        public bool Log_info(string strMsg, int nLogMode)
        {
            try
            {
                string strCheckFolder = "";
                string strFileName = "";
                string strLogMode = "";
                

                if (LogFilePath == null || LogFilePath.Length <= 0)
                {
                    GetEnvironment();
                }

                if (!System.IO.Directory.Exists(LogPath))
                {
                    System.IO.Directory.CreateDirectory(LogPath);
                }

                switch ((LOGINFO)nLogMode)
                {
                    case LOGINFO.ERROR:
                        strLogMode = LOGINFO.ERROR.ToString();
                        break;
                    case LOGINFO.WARN:
                        strLogMode = LOGINFO.WARN.ToString();
                        break;
                    case LOGINFO.FATAL:
                        strLogMode = LOGINFO.FATAL.ToString();
                        break;
                    case LOGINFO.INFO:
                    default:
                        strLogMode = LOGINFO.INFO.ToString();
                        break;
                }
                
                string LogFormat = strLogMode + "\t" +  strMsg + "\t";
                LogFormat = LogFormat.Replace("\n", "");
                LogFormat = LogFormat.Replace("\r", "");

                string logtime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss:fff");
                string writelog = logtime + "\t" + LogFormat;

                using (StreamWriter sw = File.AppendText(LogFilePath))
                {

                   sw.WriteLine(writelog);
                   sw.Flush();
                   sw.Close();
                }


            }
            catch
            {
                return false;
            }
            return true;
        }

    }
}
