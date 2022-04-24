using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Identity.NET
{
    internal partial class Crypt
    {
        internal static string Encrypt(string c, string k, string p)
        {
            byte[] clearBytes = Encoding.Unicode.GetBytes(c);
            using (Aes encryptor = Aes.Create())
            {
                string b = k + p;
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(b, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                encryptor.Padding = PaddingMode.Zeros;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    c = Convert.ToBase64String(ms.ToArray());
                };
            }
            return c;
        }
    }
}
