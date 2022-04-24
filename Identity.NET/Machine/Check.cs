using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Text;

namespace Identity.NET.Id
{
    internal class Check
    {
        /// <summary>
        /// Test the Identity_Strong key
        /// <para>If this matches the Identity key then you don't have a weak key</para>
        /// /// <param name="password">The additional password your data is secured with</param>
        /// </summary>
        /// <param name="strongIdentityKey"></param>
        /// <returns></returns>
        internal static bool StrongID(string strongIdentityKey, string password = "")
        {
            string MotherboardUUID = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig", "LastConfig", "") as string;

            string builder = "";
            if (Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM\WMI", "WindowsAIKHash", "") is byte[] WindowsAKIHash && WindowsAKIHash.Length > 0)
            {
                foreach (byte k in WindowsAKIHash)
                {
                    builder += k.ToString();
                }
            }

            string strong = builder + "-" + MotherboardUUID;
            string strong_e = Crypt.Encrypt(strong, strong.Substring(50), password);

            return strong_e == strongIdentityKey;
        }
    }
}
