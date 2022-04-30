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

using Identity.NET.Utility;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Identity.NET
{
    internal partial class Crypt
    {
        internal static string Decrypt(string c, string k, string p, string path)
        {
            c = c.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(c);
            using (Aes encryptor = Aes.Create())
            {
                string b = k + p;

                byte[] pb = Encoding.UTF8.GetBytes(path);

                byte[] salt = new byte[] { 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x4e, 0x45, 0x54, 0x2d, 0x34, 0x78, 0x37, 0x46 };

                byte[] s2 = Combine.ByteArray(salt, pb);

                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(b, s2);

                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                encryptor.Padding = PaddingMode.Zeros;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }

                    char[] charsToTrim = { '\0' };
                    var s = Encoding.Unicode.GetString(ms.ToArray());
                    c = s.TrimEnd(charsToTrim);
                };
            }
            return c;
        }
    }
}
