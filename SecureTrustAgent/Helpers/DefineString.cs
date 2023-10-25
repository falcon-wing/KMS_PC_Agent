using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTrustAgent.Helpers
{
    static class Trid
    {
        public const string TRID_GET_PCAGENT_INFO = "500201";
        public const string TRID_PC_WEB_LOGIN = "500202";
        
        public const string TRID_GET_CHALLENGE = "500203";
        public const string TRID_REQUEST_AUTH = "500204";
        public const string TRID_REQUEST_REGPUF = "500205";
        public const string TRID_REQUEST_RESETPUF = "500206";
        public const string TRID_SSH_LOGIN = "500207";

        public const string TRID_WEB_LOGOUT = "500208";

        public const string TRID_MASTERKEY_UPDATE = "500209";
        
    }

    public enum MFA_OPT_ENUM
    {
        MFA_OPT_REGPUF = 1, 
        MFA_OPT_AUTH = 2,
        MFA_OPT_RESET  = 3,
    }

    static class RET_CODE
    {
        public const string RET_CODE_OK = "000000";
        public static string RET_CODE_ERR = "000001";
    }

    static class RET_MSG
    {
        public const string RET_MSG_OK = "Success";
        public static string RET_MSG_ERR = "처리중 오류가 발생하였습니다.(000001)";
    }

    public enum APIINDEX
    {
        INDEX_PUF_REG       = 0,
        INDEX_AUTH          ,
        INDEX_SESSIONKEY_CHALLENGE  ,
        INDEX_SESSIONKEY_REQUEST    ,
        
        INDEX_RESET_SIGNATURE       ,
        INDEX_RESET_FINISH          ,
    }

    public enum API_ITEM
    {
        ITEM_TRID       = 0,
        ITEM_URL        ,
        ITEM_FUNC       ,
    }


    public struct REQUEST_API_STRUCT
    {
        /*public static string[] puf_reg = new string[]                   { "070200", "https://43.201.210.221", "/kms/admin/winagent/puf/register" };
        public static string[] puf_auth = new string[]                  { "070210", "https://43.201.210.221", "/kms/admin/winagent/puf/auth" };
        public static string[] puf_sessionkey_challenge = new string[]  { "070220", "https://43.201.210.221", "/kms/admin/winagent/puf/session-key/challenge" };
        public static string[] puf_sessionkey_request = new string[]    { "070221", "https://43.201.210.221", "/kms/admin/winagent/puf/session-key/request" };
        public static string[] puf_reset_signature = new string[]       { "070230", "https://43.201.210.221", "/kms/admin/winagent/puf/reset/signature" };
        public static string[] puf_reset_finish = new string[]          { "070231", "https://43.201.210.221", "/kms/admin/winagent/puf/reset/finish" };
        */

        public static string[] puf_reg = new string[] { "070200", "https://192.168.1.188", "/kms/admin/winagent/puf/register" };
        public static string[] puf_auth = new string[] { "070210", "https://192.168.1.188", "/kms/admin/winagent/puf/auth" };
        public static string[] puf_sessionkey_challenge = new string[] { "070220", "https://192.168.1.188", "/kms/admin/winagent/puf/session-key/challenge" };
        public static string[] puf_sessionkey_request = new string[] { "070221", "https://192.168.1.188", "/kms/admin/winagent/puf/session-key/request" };
        public static string[] puf_reset_signature = new string[] { "070230", "https://192.168.1.188", "/kms/admin/winagent/puf/reset/signature" };
        public static string[] puf_reset_finish = new string[] { "070231", "https://192.168.1.188", "/kms/admin/winagent/puf/reset/finish" };

        public static string[][] request_api = new string[][] { puf_reg, puf_auth, puf_sessionkey_challenge, puf_sessionkey_request, puf_reset_signature, puf_reset_finish };
    };


    static class MFAOption
    {
        public const string MFA_OPT_REG     = "1";
        public const string MFA_OPT_AUTH    = "2";
        public const string MFA_OPT_RESET   = "3";
    }

    static class DefineString
    {
        public const string PRODUCT_NAME                        = "SecureTrustAgent";

        public const string MENU_STATUS                         = "Status";
        public const string MENU_MAIN                           = "Main";
        public const string MENU_EXIT                           = "Exit";

        public const string YES                                 = "YES";
        public const string NO                                  = "NO";

        public const string PRODDUCT_CONFDIR                    = "Conf";
        public const string PRODDUCT_CONFFILE                   = "rotconfig.ini";

        public const string SSH_SECTION                         = "SSH_SERVICE_CONF";
        public const string SSH_LISTEN_PORT                     = "LISTEN_PORT";
        public const string SSH_DEFAULT_IP                      = "DEFAULT_IP";
        public const string SSH_USER_ANYIP                      = "USE_ANYIP";


        public const int MAX_BUFFER_SIZE                        = 4096;

        public const string KMS_ADMIN_WEB_CONF = "KMS_ADMIN_WEB_CONF";
        public const string HTTP_LISTENER_CONF                  = "HTTP_LISTENER_CONF";
        public const string HTTP_LISTENER_PORT                  = "HTTP_LISTENER_PORT";

        public const string WEB_SECTION                         = "WEB_SERVICE_CONF";
        public const string WEB_LISTEN_PORT                     = "LISTEN_PORT";
        public const string WEB_DEFAULT_IP                      = "DEFAULT_IP";
        public const string WEB_USER_ANYIP                      = "USE_ANYIP";

        

        public const string APP_LANGUAGE_SECTION                = "APP_LANGUAGE_CONF";
        public const string APP_LANGUAGE_STRING                 = "APP_LANGUAGE";

        public const string APP_DEFAULT_CONF                    = "APP_DEFAULT_CONF";
        public const string SUPPORT_SSH                         = "SUPPORT_SSH";
        public const string WEB_ADDMIN_PAGEURL                  = "WEB_ADDMIN_PAGEURL";
        public const string WEB_LOGIN_PAGEURL                   = "WEB_LOGIN_PAGEURL";
        public const string WEB_LOGIN_PAGEPORT                  = "WEB_LOGIN_PAGEPORT";
        public const string WEB_ADMIN_PAGEPORT                  = "WEB_ADMIN_PAGEPORT";

        /*
         * 
         */
        public const string CUSTOM_CONF                         = "CUSTOM_CONF";
        public const string USE_CUSTOM                          = "USE_CUSTOM";
        public const string VENDERNAME                          = "VENDERNAME";
        public const string VENDER_SLOGANMSG                    = "VENDER_SLOGANMSG";

        /*
         * 
         */
        public const string WEB_JSON_SUCCESS_RETCODE            = "000000";
        public const string WEB_JSON_SUCCESS_RETMSG             = "성공입니다.";

        /*
         * 
         */
        //public const string WEB_REQ_
        //public const string WEBSOCK_JSON_TR
        /*
         * 
         */
        public const string WEBSOCK_JSON_TRID_WEBADMIN_SIGNIN   = "500101";
        public const string WEBSOCK_JSON_TRID_WEBADMIN_RESIGNUP = "500102";
        public const string WEBSOCK_JSON_TRID_WEBADMIN_SIGNUP   = "500103";
        public const string WEBSOCK_JSON_TRID_WEBADMIN_SIGNOUT  = "500104";
        public const string WEBSOCK_JSON_TRID_SSH_SIGNIN        = "500105";
        public const string WEBSOCK_JSON_TRID_WEBADMIN_LOGOFF   = "500106";

        public const string WEBSOCK_JSON_TRID_GETCHALLENGE      = "500203";
        public const string WEBSOCK_JSON_TRID_REQ_AUTH          = "500204";
        public const string WEBSOCK_JSON_TRID_REQ_REGISTRYPUF   = "500205";
        public const string WEBSOCK_JSON_TRID_REQ_RESETPUF      = "500206";


        public const string WEBREQ_JSON_TRID_REG = "070200";
        public const string WEBREQ_JSON_TRID_AUTH = "070210";
        public const string WEBREQ_JSON_TRID_SESSIONKEY_CHALLENGE = "070220";
        public const string WEBREQ_JSON_TRID_SESSIONKEY_REQUEST = "070221";
        public const string WEBREQ_JSON_TRID_RESET_SIGNATURE = "070230";
        public const string WEBREQ_JSON_TRID_RESET_FINISH = "0X0231";



        /*
         * 
         */
        public const string WEB_PAGE_TITLE_LOGIN = "KMS LOGIN";
        public const string WEB_PAGE_TITLE_ADMIN = "KMS MANAGER PAGE";
    }

    public struct WEB_REQ_API_ARRAY_STRUCT
    {
        public static string[] req_puf_web_auth         = new string[] { "500101", "/kms/mfa/public/puf/auth"       , "auth_puf" };
        public static string[] req_puf_web_re_signup    = new string[] { "500102", "/kms/mfa/public/puf/re-register", "re-register_puf" };
        public static string[] req_puf_web_signup       = new string[] { "500103", "/kms/mfa/public/puf/signup"     , "signup_puf" };
        public static string[] req_puf_web_signout      = new string[] { "500104", "/kms/mfa/public/puf/signout"    , "signout_puf" };

        public static string[] req_puf_ssh_auth         = new string[] { "500201", "/kms/mfa/public/puf/auth", "auth_puf" };
        public static string[] req_puf_ssh_re_signup    = new string[] { "500202", "/kms/mfa/public/puf/re-register", "re-register_puf" };
        public static string[] req_puf_ssh_signup       = new string[] { "500203", "/kms/mfa/public/puf/signup", "signup_puf" };
        public static string[] req_puf_ssh_signout      = new string[] { "500204", "/kms/mfa/public/puf/signout", "signout_puf" };
        public static string[] req_puf_ssh_challenge    = new string[] { "500205", "/kms/mfa/public/auth/session-key/challenge", "challenge_session_key" };
        public static string[] req_puf_ssh_req_challenge = new string[] { "500206", "/kms/mfa/public/auth/session-key/request", "request_session_key" };
    }
}
