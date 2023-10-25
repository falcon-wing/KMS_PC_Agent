using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Security.RightsManagement;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Windows.Automation;

namespace SecureTrustAgent
{
    internal class JSON_DataClass
    {
        public struct JSON_HDADER_STRUCT_OF_WEB
        {
            public string trId;
            public string rtnCode;
            public string rtnMessage;
            public string Authorization;
            public string userId;
        }

        public struct JSON_TOKEN_STRUCT_OF_WEB
        {
            public string accessToken;
            public string expired;
            public string expiredCount;
        }

        public struct JSON_MFA_STRUCT_OF_WEB
        {
            public string mafOption;
            public JSON_TOKEN_STRUCT_OF_WEB token;
        }

        public struct ICTK_JSON_SUBSTRUCT_ECC
        {
            public string signAlgorithm;
            public string signature;
        }

        public struct ICTK_JSON_SUBSTRUCT_PQC
        {
            public string signAlgorithm;
            public string signature;
        }

        public struct ICTK_JSON_SUBSTRUCT_SIGNATURE
        {
            //public ICTK_JSON_SUBSTRUCT_ECC ecc;
            public ICTK_JSON_SUBSTRUCT_PQC pqc;
        }

        public struct ICTK_JSON_SIMPLE_HEADER_STRUCT
        {
            public string trId;
        }

        public struct ICTK_JSON_AUTH_BODY_STRUCT
        {
            public string uId;
            public string sessionId;

            public ICTK_JSON_SUBSTRUCT_SIGNATURE signature;

        }
        

        public struct JSON_MFA_STRUCT_OF_WEB2ND_MFA
        {
            public string challenge;
            public string sessionId;
            public int mfaOption;
            public JSON_TOKEN_STRUCT_OF_WEB token;
        }


        public struct ICTK_JSON_AUTH_STRUCT
        {
            public ICTK_JSON_SIMPLE_HEADER_STRUCT header;

            public ICTK_JSON_AUTH_BODY_STRUCT body;
        }

        public struct ICTK_JSON_RES_SESSIONKEY_CHALLENGE_STRUCT
        {
            public string sessionId;
            public string kePk;
        }

        public struct ICTK_JSON_REQ_SESSIONKEY_REQUEST_STRUCT
        {
            public string uId;
            public string sessionId;
            public string encKey;
        }

        public struct ICTK_JSON_RES_SESSIONKEY_REQUEST_STRUCT
        {
            public string encSessionKey;
            public string hmacStr;
        }


        public struct JSON_MFA_STRUCT_OF_WEB2ND
        {
            public JSON_MFA_STRUCT_OF_WEB2ND_MFA mfa;
            public string userId;
        }



        public struct JSON_BODY_STRUCT_OF_WEB
        {
            public string uId;
            public string sessionId;
            public string userId;
            public string sessionKey;
            public string challenge;
            public string sign;
            public string crt;
            public JSON_MFA_STRUCT_OF_WEB mfa;
        }

        public struct JSON_STRUCT_OF_WEB 
        {
            public JSON_HDADER_STRUCT_OF_WEB header;
            public JSON_BODY_STRUCT_OF_WEB body;
        }

        public struct JSON_BODY_STRUCT_OF_WEB_UID
        {
            public string uid;
            public string pc_info;
        }

        public struct JSON_STGRUCT_OF_WEB_REQ_UID
        {
            public JSON_HDADER_STRUCT_OF_WEB header;
            public JSON_BODY_STRUCT_OF_WEB_UID body;
           
        }

        public struct JSON_STGRUCT_OF_WEB_2ND
        {
            public JSON_HDADER_STRUCT_OF_WEB Header;
            public JSON_MFA_STRUCT_OF_WEB2ND Body;

        }

        public struct JSON_REQ_API_HEADER
        {
            public string trId;
            public string Authorization;
        }

        public struct JSON_REQ_API_BODY
        {
            public string uId;
            public string userId;
            public string crt;
            public string sessionId;
            public string encKey;
            public string rand;

        }

        public struct JSON_REQ_STRUCT
        {
            public JSON_REQ_API_HEADER header;
            public JSON_REQ_API_BODY body;
        }

        public struct JSON_RES_API_HEADER
        {
            public string trId;
            public string rtnCode;
            public string rtnMessage;
        }

        public struct JSON_REQ_BROWSERTOKKEN_STRUCT_V2
        {
            public string accessToken;
            public string expired;
            public string expiredCount;
            public string uId;
        }

        public struct JSON_REQ_BROWSERTOKKEN_STRUCT
        {
            public string accessToken;
            public string expired;
            public string expiredCount;
        }

        public struct JSON_REQ_AGENTTOKKEN_STRUCT
        {
            public string accessToken;
            public string expired;
        }

        public struct JSON_RES_AUTH_BODY_STRUCT
        {
            public string sessionId;
            public JSON_REQ_BROWSERTOKKEN_STRUCT browserToken;
            public JSON_REQ_AGENTTOKKEN_STRUCT agentToken;
        }

        public struct JSON_REQ_RESET_SIGNATURE_BODY_STRUCT
        {
            public string uId;
            public string rand;
        }

        public struct JSON_RES_AUTH_STRUCT
        {
            public JSON_RES_API_HEADER header;
            public JSON_RES_AUTH_BODY_STRUCT body;
        }

        public struct ICTK_JSON_REQ_SESSION_KEY_CHALLENGE_BODY
        {
            public string uId;
            public string sessionId;
        }

        public struct ICTK_JSON_REQ_SESSION_KEY_CHALLENGE_STRUCT
        {
            public ICTK_JSON_SIMPLE_HEADER_STRUCT header;
            public ICTK_JSON_REQ_SESSION_KEY_CHALLENGE_BODY body;
        }

        public struct ICTK_JSON_RES_SESSION_KEY_CHALLENGE_STATUCT
        {
            public JSON_RES_API_HEADER header;
            public ICTK_JSON_RES_SESSIONKEY_CHALLENGE_STRUCT body;
        }


        public struct ICTK_JSON_REQ_SESSION_KEY_REQUEST_STATUCT
        {
            public ICTK_JSON_SIMPLE_HEADER_STRUCT header;
            public ICTK_JSON_REQ_SESSIONKEY_REQUEST_STRUCT body;
        }

        public struct ICTK_JSON_RES_SESSION_KEY_REQUEST_STATUCT
        {
            public JSON_RES_API_HEADER header;
            public ICTK_JSON_RES_SESSIONKEY_REQUEST_STRUCT body;
        }

        public struct ICTK_JSON_RES_SESSION_KEY_RETBODY_STRUCT
        {
            public string sessionKey;
            //public string uId;
            public JSON_REQ_BROWSERTOKKEN_STRUCT_V2 browserToken;
        }

        public struct ICTK_JSON_RES_SESSION_KEY_RESULT_STRUCT
        {
            public JSON_RES_API_HEADER header;
            public ICTK_JSON_RES_SESSION_KEY_RETBODY_STRUCT body;
        }

        public struct ICTK_JSON_REQ_RESET_SIGNATURE
        {
            public ICTK_JSON_SIMPLE_HEADER_STRUCT header;
            public JSON_REQ_RESET_SIGNATURE_BODY_STRUCT body;
        }

        public struct ICTK_JSON_RES_RESET_SIGNATURE_BODY
        {
            public string sign;
        }

        public struct ICTK_JSON_RES_RESET_SIGNATURE
        {
            public JSON_RES_API_HEADER header;
            public ICTK_JSON_RES_RESET_SIGNATURE_BODY body;
        }

        public struct ICTK_JSON_RES_RESET_FIN_HEADER
        {
            public string trId;
        }
        public struct ICTK_JSON_RES_RESET_FIN_BODY
        {
            public string uId;
        }

        public struct ICTK_JSON_RES_RESET_FIN
        {
            public ICTK_JSON_RES_RESET_FIN_HEADER header;
            public ICTK_JSON_RES_RESET_FIN_BODY body;
        }

        public struct ICTK_JSON_REQ_MASTERKEY_UPDATE_HEADER
        {
            public string trId;
        }

        public struct ICTK_JSON_REQ_MASTERKEY_UPDATE_BODY
        {
            public string challenge_1;
            public string challenge_2;
        }

        public struct ICTK_JSON_REQ_MASTERKEY_UPDATE
        {
            public ICTK_JSON_REQ_MASTERKEY_UPDATE_HEADER header;
            public ICTK_JSON_REQ_MASTERKEY_UPDATE_BODY body;
        }

        

        public struct ICTK_JSON_RES_MASTERKEY_UPDATE_BODY
        {
            public string challenge_1;
            public string access_value_1;
            public string challenge_2;
            public string access_value_2;

        }

        public struct ICTK_JSON_RES_MASTERKEY_UPDATE
        {
            public JSON_RES_API_HEADER header;
            public ICTK_JSON_RES_MASTERKEY_UPDATE_BODY body;
        }

        public struct ICTK_JSON_RES_RESET_RET_BODY
        {
            public string uId;
            public int mfaOption;


        }

        public struct ICTK_JSON_RES_ERROR_RET
        {
            public JSON_RES_API_HEADER header;
        }

        public struct ICTK_JSON_RES_RESET_RET
        {
            public JSON_RES_API_HEADER header;
            public ICTK_JSON_RES_RESET_RET_BODY body;

        }

        public struct JSON_RES_PAI_BODY
        {
            public string sessionId;
            public JSON_REQ_BROWSERTOKKEN_STRUCT browserToken;
            public JSON_REQ_AGENTTOKKEN_STRUCT agentToken;
            public string kePk;
            public string encSessionKey;
            public string hmacStr;
            public string sign;
            public string uId;
        }
    }
}
