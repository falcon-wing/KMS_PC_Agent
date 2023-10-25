using CefSharp.DevTools.Network;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SecureTrustAgent.Helpers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using static SecureTrustAgent.JSON_DataClass;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.Tab;

namespace SecureTrustAgent.TRANS
{
    public class Response_http
    {
        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("header")]
        public header Header { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("body")]
        public body Body { get; set; }
    }

    public class header : Response_http
    {
        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("trId")]
        public string TrId { get; set; }
        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("rtnCode")]
        public string RtnCode { get; set; }
        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("rtnMessage")]
        public string RtnMessage { get; set; }
    }

    public class body : Response_http
    {
        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("challenge")]
        public string Challenge { get; set; }
        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("sessionId")]
        public string SessionId { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("sessionKey")]
        public string SessionKey { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("token")]
        public token toekn { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("browserToken")]
        public token BrowserToken { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("agentToken")]
        public token AgentToken { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("kePk")]
        public string KePk { get; set; }
        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("encMediaKey")]
        public string EncMediaKey { get; set; }

        /// <summary>
        /// 
        /// </summary>
        [JsonProperty("encSessionKey")]
        public string EncSessionKey { get; set; }

        
        [JsonProperty("sign")]
        public string Sign { get; set; }

        [JsonProperty("hmacStr")]
        public string HmacStr { get; set; }

        [JsonProperty("userId")]
        public string UserId { get; set; }

        [JsonProperty("rawBytes")]
        public string RawBytes { get; set; }

        [JsonProperty("uid")]
        public string Uid { get; set; }

        
    }

    public class token
    {
        [JsonProperty("accessToken")]
        public string AccessToken { get; set; }

        [JsonProperty("expired")]
        public string Expired { get; set; }
    }

    public class browserToken
    {
        [JsonProperty("accessToken")]
        public string AccessToken { get; set; }

        [JsonProperty("expired")]
        public string Expired { get; set; }
    }

    public class agentToken
    {
        [JsonProperty("accessToken")]
        public string AccessToken { get; set; }

        [JsonProperty("expired")]
        public string Expired { get; set; }
    }

    internal class RestApiClass
    {
        UtilsClass utils = new UtilsClass();
        public bool InitWebReuestObject(ref HttpWebRequest httpRequest, string Authorization)
        {
            httpRequest.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            httpRequest.Accept = "application/json";
            httpRequest.Method = "POST";
            httpRequest.ContentType = "application/json";
            httpRequest.Headers.Add("Authorization", Authorization);

            return true;
        }

        public bool httpWebRequest_auth(ICTK_JSON_AUTH_STRUCT req_json, ref JSON_RES_AUTH_STRUCT resp_json, string accesstoken, string sessionId)
        {
            string strHttpUrl = string.Empty;
            string json_str = string.Empty;
            StringBuilder dParams = new StringBuilder();
            string[] TarApi = REQUEST_API_STRUCT.request_api[(int)APIINDEX.INDEX_AUTH];

           
            string strUrl = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.KMS_ADMIN_WEB_CONF);

            strHttpUrl = strUrl + TarApi[(int)API_ITEM.ITEM_FUNC];

            StringBuilder dataParams = new StringBuilder();
            json_str = JsonConvert.SerializeObject(req_json);
            dataParams.Append(json_str);

            byte[] byteDParams = UTF8Encoding.UTF8.GetBytes(dataParams.ToString());
            var httpWebRequest = (HttpWebRequest)WebRequest.Create(strHttpUrl);
            InitWebReuestObject(ref httpWebRequest, accesstoken);
            if (httpWebRequest.RequestUri.Scheme == Uri.UriSchemeHttps) { }

            Stream dStream = httpWebRequest.GetRequestStream();
            dStream.Write(byteDParams, 0, byteDParams.Length);
            dStream.Close();

            Thread.Sleep(10);
            using (WebResponse webResponse = httpWebRequest.GetResponse())
            using (Stream stream = webResponse.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                if (webResponse == null)
                {
                    return false;
                }

                Response_http response_json_struct;
                HttpWebResponse httpResponse = (HttpWebResponse)webResponse;
                string read_json = reader.ReadToEnd();
                var obj = JObject.Parse(read_json);
                response_json_struct = JsonConvert.DeserializeObject<Response_http>(read_json);

                if (httpResponse.StatusCode == HttpStatusCode.OK && String.Compare(response_json_struct.Header.RtnCode, RET_CODE.RET_CODE_OK) == 0)
                {
                    resp_json.header.trId = (string)response_json_struct.Header.TrId.ToString();
                    resp_json.header.rtnCode = (string)response_json_struct.Header.RtnCode.ToString();
                    resp_json.header.rtnMessage = (string)response_json_struct.Header.RtnMessage.ToString();

                    resp_json.body.sessionId = response_json_struct.Body.SessionId.ToString();
                    resp_json.body.browserToken.accessToken = response_json_struct.Body.BrowserToken.AccessToken.ToString();
                    resp_json.body.browserToken.expired = response_json_struct.Body.BrowserToken.Expired.ToString();
                    resp_json.body.browserToken.expiredCount = response_json_struct.Body.BrowserToken.Expired.ToString();

                    resp_json.body.agentToken.accessToken = response_json_struct.Body.AgentToken.AccessToken.ToString();
                    resp_json.body.agentToken.expired = response_json_struct.Body.AgentToken.Expired.ToString();
                }
                else
                {
                    if (response_json_struct.Header.RtnMessage.Length > 0)
                    {
                        CustomMessageBoxClass.Show(Localization.res.STR_WORKERROR_TITLE, response_json_struct.Header.RtnMessage, MessageBoxButton.OK);
                    }
                    else
                    {
                        CustomMessageBoxClass.Show(Localization.res.STR_WORKERROR_TITLE, RET_MSG.RET_MSG_ERR, MessageBoxButton.OK);
                    }

                    return false;
                }

            }
            return true;
        }

        public bool httpWebRequest_sessionkey_challenge(ICTK_JSON_REQ_SESSION_KEY_CHALLENGE_STRUCT req_json, ref ICTK_JSON_RES_SESSION_KEY_CHALLENGE_STATUCT resp_json, string accesstoken, string sessionId)
        {
            string strHttpUrl = string.Empty;
            string json_str = string.Empty;
            StringBuilder dParams = new StringBuilder();
            string[] TarApi = REQUEST_API_STRUCT.request_api[(int)APIINDEX.INDEX_SESSIONKEY_CHALLENGE];
            string strUrl = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.KMS_ADMIN_WEB_CONF);
            strHttpUrl = strUrl + TarApi[(int)API_ITEM.ITEM_FUNC];

            StringBuilder dataParams = new StringBuilder();
            json_str = JsonConvert.SerializeObject(req_json);
            dataParams.Append(json_str);

            byte[] byteDParams = UTF8Encoding.UTF8.GetBytes(dataParams.ToString());
            var httpWebRequest = (HttpWebRequest)WebRequest.Create(strHttpUrl);
            InitWebReuestObject(ref httpWebRequest, accesstoken);
            if (httpWebRequest.RequestUri.Scheme == Uri.UriSchemeHttps) { }

            Stream dStream = httpWebRequest.GetRequestStream();
            dStream.Write(byteDParams, 0, byteDParams.Length);
            dStream.Close();

            Thread.Sleep(10);
            using (WebResponse webResponse = httpWebRequest.GetResponse())
            using (Stream stream = webResponse.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                if (webResponse == null)
                {
                    return false;
                }

                Response_http response_json_struct;
                HttpWebResponse httpResponse = (HttpWebResponse)webResponse;
                string read_json = reader.ReadToEnd();
                var obj = JObject.Parse(read_json);
                response_json_struct = JsonConvert.DeserializeObject<Response_http>(read_json);

                if (httpResponse.StatusCode == HttpStatusCode.OK)
                {
                    resp_json.header.trId = (string)response_json_struct.Header.TrId.ToString();
                    resp_json.header.rtnCode = (string)response_json_struct.Header.RtnCode.ToString();
                    resp_json.header.rtnMessage = (string)response_json_struct.Header.RtnMessage.ToString();

                    resp_json.body.sessionId = (string)response_json_struct.Body.SessionId.ToString();
                    resp_json.body.kePk = (string)response_json_struct.Body.KePk.ToString();
                }

            }
            return true;
        }

        public bool httpWebRequest_sessionkey_request(ICTK_JSON_REQ_SESSION_KEY_REQUEST_STATUCT req_json, ref ICTK_JSON_RES_SESSION_KEY_REQUEST_STATUCT resp_json, string accesstoken, string sessionId)
        {
            string strHttpUrl = string.Empty;
            string json_str = string.Empty;
            StringBuilder dParams = new StringBuilder();
            string[] TarApi = REQUEST_API_STRUCT.request_api[(int)APIINDEX.INDEX_SESSIONKEY_REQUEST];
            string strUrl = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.KMS_ADMIN_WEB_CONF);
            strHttpUrl = strUrl + TarApi[(int)API_ITEM.ITEM_FUNC];

            StringBuilder dataParams = new StringBuilder();
            json_str = JsonConvert.SerializeObject(req_json);
            dataParams.Append(json_str);

            byte[] byteDParams = UTF8Encoding.UTF8.GetBytes(dataParams.ToString());
            var httpWebRequest = (HttpWebRequest)WebRequest.Create(strHttpUrl);
            InitWebReuestObject(ref httpWebRequest, accesstoken);
            if (httpWebRequest.RequestUri.Scheme == Uri.UriSchemeHttps) { }

            Stream dStream = httpWebRequest.GetRequestStream();
            dStream.Write(byteDParams, 0, byteDParams.Length);
            dStream.Close();

            Thread.Sleep(10);
            using (WebResponse webResponse = httpWebRequest.GetResponse())
            using (Stream stream = webResponse.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                if (webResponse == null)
                {
                    return false;
                }

                Response_http response_json_struct;
                HttpWebResponse httpResponse = (HttpWebResponse)webResponse;
                string read_json = reader.ReadToEnd();
                var obj = JObject.Parse(read_json);
                response_json_struct = JsonConvert.DeserializeObject<Response_http>(read_json);

                if (httpResponse.StatusCode == HttpStatusCode.OK)
                {
                    resp_json.header.trId = (string)response_json_struct.Header.TrId.ToString();
                    resp_json.header.rtnCode = (string)response_json_struct.Header.RtnCode.ToString();
                    resp_json.header.rtnMessage = (string)response_json_struct.Header.RtnMessage.ToString();

                    resp_json.body.encSessionKey = response_json_struct.Body.EncSessionKey;
                    resp_json.body.hmacStr = response_json_struct.Body.HmacStr;
                }

            }
            return true;
        }

        public bool httpWebRequest_reset_signature(ICTK_JSON_REQ_RESET_SIGNATURE req_json, ref ICTK_JSON_RES_RESET_SIGNATURE resp_json, string accesstoken, string sessionId)
        {
            string strHttpUrl = string.Empty;
            string json_str = string.Empty;
            StringBuilder dParams = new StringBuilder();
            string[] TarApi = REQUEST_API_STRUCT.request_api[(int)APIINDEX.INDEX_RESET_SIGNATURE];
            string strUrl = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.KMS_ADMIN_WEB_CONF);
            strHttpUrl = strUrl + TarApi[(int)API_ITEM.ITEM_FUNC];

            StringBuilder dataParams = new StringBuilder();
            json_str = JsonConvert.SerializeObject(req_json);
            dataParams.Append(json_str);

            byte[] byteDParams = UTF8Encoding.UTF8.GetBytes(dataParams.ToString());
            var httpWebRequest = (HttpWebRequest)WebRequest.Create(strHttpUrl);
            InitWebReuestObject(ref httpWebRequest, accesstoken);
            if (httpWebRequest.RequestUri.Scheme == Uri.UriSchemeHttps) { }

            Stream dStream = httpWebRequest.GetRequestStream();
            dStream.Write(byteDParams, 0, byteDParams.Length);
            dStream.Close();

            Thread.Sleep(10);
            using (WebResponse webResponse = httpWebRequest.GetResponse())
            using (Stream stream = webResponse.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                if (webResponse == null)
                {
                    return false;
                }

                Response_http response_json_struct;
                HttpWebResponse httpResponse = (HttpWebResponse)webResponse;
                string read_json = reader.ReadToEnd();
                var obj = JObject.Parse(read_json);
                response_json_struct = JsonConvert.DeserializeObject<Response_http>(read_json);

                if (httpResponse.StatusCode == HttpStatusCode.OK)
                {
                    resp_json.header.trId = (string)response_json_struct.Header.TrId.ToString();
                    resp_json.header.rtnCode = (string)response_json_struct.Header.RtnCode.ToString();
                    resp_json.header.rtnMessage = (string)response_json_struct.Header.RtnMessage.ToString();

                    resp_json.body.sign = (string)response_json_struct.Body.Sign.ToString();
                }

            }
            return true;
        }

        public bool httpWebRequest_reset_fin(ICTK_JSON_RES_RESET_FIN req_json, ref ICTK_JSON_RES_RESET_FIN resp_json, string accesstoken, string sessionId)
        {
            string strHttpUrl = string.Empty;
            string json_str = string.Empty;
            StringBuilder dParams = new StringBuilder();
            string[] TarApi = REQUEST_API_STRUCT.request_api[(int)APIINDEX.INDEX_RESET_FINISH];
            string strUrl = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.KMS_ADMIN_WEB_CONF);
            strHttpUrl = strUrl + TarApi[(int)API_ITEM.ITEM_FUNC];

            StringBuilder dataParams = new StringBuilder();
            json_str = JsonConvert.SerializeObject(req_json);
            dataParams.Append(json_str);

            byte[] byteDParams = UTF8Encoding.UTF8.GetBytes(dataParams.ToString());
            var httpWebRequest = (HttpWebRequest)WebRequest.Create(strHttpUrl);
            InitWebReuestObject(ref httpWebRequest, accesstoken);
            if (httpWebRequest.RequestUri.Scheme == Uri.UriSchemeHttps) { }

            Stream dStream = httpWebRequest.GetRequestStream();
            dStream.Write(byteDParams, 0, byteDParams.Length);
            dStream.Close();

            Thread.Sleep(10);
            using (WebResponse webResponse = httpWebRequest.GetResponse())
            using (Stream stream = webResponse.GetResponseStream())
            using (StreamReader reader = new StreamReader(stream))
            {
                if (webResponse == null)
                {
                    return false;
                }

                Response_http response_json_struct;
                HttpWebResponse httpResponse = (HttpWebResponse)webResponse;
                string read_json = reader.ReadToEnd();
                var obj = JObject.Parse(read_json);
                response_json_struct = JsonConvert.DeserializeObject<Response_http>(read_json);

                if (httpResponse.StatusCode == HttpStatusCode.OK)
                {
                    resp_json.header.trId = (string)response_json_struct.Header.TrId.ToString();
                }

            }
            return true;
        }

        public bool httpWebRequest(int nIndex, JSON_STRUCT_OF_WEB req_json, ref JSON_STRUCT_OF_WEB resp_json )
        {
            string strHttpUrl = string.Empty;
            string json_str = string.Empty;
            StringBuilder dParams = new StringBuilder();
            string[] TarApi = REQUEST_API_STRUCT.request_api[nIndex];
            string strUrl = utils.get_conf(DefineString.WEB_LOGIN_PAGEURL, DefineString.KMS_ADMIN_WEB_CONF);
            strHttpUrl = strUrl + TarApi[(int)API_ITEM.ITEM_FUNC];

            StringBuilder dataParams = new StringBuilder();
            json_str = JsonConvert.SerializeObject(req_json);

            dataParams.Append(json_str);
            /*
             */
            byte[] byteDParams = UTF8Encoding.UTF8.GetBytes(dataParams.ToString());

            var httpWebRequest = (HttpWebRequest)WebRequest.Create(strHttpUrl);

            InitWebReuestObject(ref httpWebRequest, req_json.body.mfa.token.accessToken);

            if (httpWebRequest.RequestUri.Scheme == Uri.UriSchemeHttps)
            {
               // ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
            }

            Stream dStream = httpWebRequest.GetRequestStream();
            dStream.Write(byteDParams, 0, byteDParams.Length);
            dStream.Close();

            Thread.Sleep(10);

            using (WebResponse webResponse = httpWebRequest.GetResponse())
            using (Stream stream = webResponse.GetResponseStream()) 
            using (StreamReader reader = new StreamReader(stream))
            {
                if (webResponse == null)
                {
                    return false;
                }

                Response_http response_json_struct;
                HttpWebResponse httpResponse = (HttpWebResponse)webResponse;
                string read_json = reader.ReadToEnd();
                var obj = JObject.Parse(read_json);

                response_json_struct = JsonConvert.DeserializeObject<Response_http>(read_json);

                if (httpResponse.StatusCode == HttpStatusCode.OK)
                {
                    resp_json.header.trId = (string)response_json_struct.Header.TrId.ToString();
                    resp_json.header.rtnCode = (string)response_json_struct.Header.RtnCode.ToString();
                    resp_json.header.rtnMessage = (string)response_json_struct.Header.RtnMessage.ToString();

                    if (string.Compare(resp_json.header.trId, DefineString.WEBREQ_JSON_TRID_REG) == 0)
                    {
                        //resp_json.body.challenge = response_json_struct.Body.Challenge.ToString();
                    }

                    else if (string.Compare(resp_json.header.trId, DefineString.WEBREQ_JSON_TRID_AUTH) == 0)
                    {
                        resp_json.body.sessionKey = response_json_struct.Body.SessionKey.ToString();
                    }

                    else if (string.Compare(resp_json.header.trId, DefineString.WEBREQ_JSON_TRID_SESSIONKEY_CHALLENGE) == 0)
                    {

                    }

                    else if (string.Compare(resp_json.header.trId, DefineString.WEBREQ_JSON_TRID_SESSIONKEY_REQUEST) == 0)
                    {
                        resp_json.body.sign = response_json_struct.Body.Sign.ToString();
                    }

                    else if (string.Compare(resp_json.header.trId, DefineString.WEBREQ_JSON_TRID_RESET_SIGNATURE) == 0)
                    {

                    }

                    else if (string.Compare(resp_json.header.trId, DefineString.WEBREQ_JSON_TRID_RESET_FINISH) == 0)
                    {

                    }

                    else
                    {

                    }
                }
                else
                {

                }
            }

            return true;
        }
    }
}
