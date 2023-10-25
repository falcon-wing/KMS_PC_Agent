using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.RightsManagement;
using System.Text;
using System.Threading.Tasks;

namespace SecureTrustAgent.Helpers
{
    public class DefineStruct
    {
        public struct AGENT_INFO
        {
            public string uid;
            public string pc_info;
            public string crt;
        }
    }
}
