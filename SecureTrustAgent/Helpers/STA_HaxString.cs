using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureTrustAgent.Helpers
{
    public class STA_HaxString
    {
        public static byte[] convzeropadding(byte[] org)
        {
            int num = org.Length / 16;
            int num2 = org.Length % 16;
            int num3 = num;
            num3 += ((num2 > 0) ? 1 : 0);
            num3 = Math.Max(num3, 1);
            int num4 = num3 * 16;
            byte[] array = new byte[num4];
            Buffer.BlockCopy(org, 0, array, 0, org.Length);
            return array;
        }

        public static byte[] StringToByteArray(string hex)
        {
            hex = hex.Replace(" ", "");
            return (from x in Enumerable.Range(0, hex.Length)
                    where x % 2 == 0
                    select Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
        }

        public static string ByteArrayToString(byte[] ba)
        {
            string text = BitConverter.ToString(ba);
            return text.Replace("-", "");
        }

        public static string TextToHexString(string text)
        {
            return TextToHexString(text, Encoding.UTF8);
        }

        public static string TextToHexString(string text, Encoding enc)
        {
            return TextToHexString(text, enc, isZeropadding: false);
        }

        public static string TextToHexString(string text, bool isZeropadding)
        {
            return TextToHexString(text, Encoding.UTF8, isZeropadding);
        }

        public static string TextToHexString(string text, Encoding enc, bool isZeropadding)
        {
            byte[] array = enc.GetBytes(text);
            if (isZeropadding)
            {
                array = convzeropadding(array);
            }

            return ByteArrayToString(array);
        }

        public static string HexStringToText(string hexStr)
        {
            return HexStringToText(hexStr, Encoding.UTF8);
        }

        public static string HexStringToText(string hexStr, Encoding enc)
        {
            return enc.GetString(StringToByteArray(hexStr));
        }

        public static byte[] HexStringToByteArray(string hexStr)
        {
            return StringToByteArray(hexStr);
        }

        public static string ByteArrayToHexStr(byte[] buffer)
        {
            return ByteArrayToString(buffer);
        }
    }
}
