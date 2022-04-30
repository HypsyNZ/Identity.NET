/*
*MIT License
*
*Copyright (c) 2022 S Christison
*
*Permission is hereby granted, free of charge, to any person obtaining a copy
*of this software and associated documentation files (the "Software"), to deal
*in the Software without restriction, including without limitation the rights
*to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
*copies of the Software, and to permit persons to whom the Software is
*furnished to do so, subject to the following conditions:
*
*The above copyright notice and this permission notice shall be included in all
*copies or substantial portions of the Software.
*
*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
*OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
*SOFTWARE.
*/

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
            string strong_e = Crypt.Encrypt(strong, strong.Substring(50), password, Machine.Path);

            return strong_e == strongIdentityKey;
        }
    }
}
