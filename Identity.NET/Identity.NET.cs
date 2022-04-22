using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Identity.NET
{
    /// <summary>
    /// Provides a Unique Identity for this PC
    /// <para>Includes Methods to Encrypt or Decrypt strings based on that Identity and an Optional Password</para>
    /// </summary>
    public class UniqueIdentity
    {
        internal static string UniqueID = null;
        internal static bool UUID = false;
        internal static bool Hash = false;
        internal static bool Seed = false;
        internal static bool Started = false;
        internal static string Path = "";

        /// <summary>
        /// Initializes the Unique Identity for this PC
        /// </summary>
        /// <param name="useStrongIdentity">True if strong identity should be used, strong identity doesn't change if the user deletes the keys</param>
        /// <param name="pathToIdentity">The registry path for the identity</param>
        /// <param name="password">The additional password your data is secured with</param>
        /// <exception cref="Exception">Throws when identity is weak</exception>
        public static void Initialize(bool useStrongIdentity = true, string pathToIdentity = "", string password = "")
        {
            Path = pathToIdentity;

            string ID = Registry.GetValue(Path, "Identity", "") as string;
            string IDW = Registry.GetValue(Path, "Identity_Weak", "") as string;
            string IDS = Registry.GetValue(Path, "Identity_Strong", "") as string;

            if (string.IsNullOrEmpty(ID) || string.IsNullOrEmpty(IDS) || string.IsNullOrEmpty(IDW))
            {
                GetNewMachineID(useStrongIdentity, password);
            }
            else
            {
                if (ID != IDS && useStrongIdentity)
                {
                    throw new Exception("Identity is Weak");
                }

                if (useStrongIdentity)
                {
                    if (!CheckStrongID(IDS, password))
                    {
                        throw new Exception("Identity Is Weak");
                    };
                }

                string half = ID.Substring(50);
                if (!string.IsNullOrEmpty(half))
                {
                    UniqueID = Decrypt(ID, half, password);
                }
            }

            Started = true;
        }

        /// <summary>
        /// Encrypt a string using the Unique Identity of this PC and Optional Password
        /// </summary>
        /// <param name="clearText">The plain text</param>
        /// <param name="password">The additional password your data is to be secured with</param>
        /// <returns></returns>
        public static string Encrypt(string clearText, string password = "")
        {
            if (!Started) { Initialize(); }
            if (UniqueID == null) { throw new Exception("Must provide Identity"); }

            return Encrypt(clearText, UniqueID, password);
        }

        /// <summary>
        /// Decrypt a string using the Unique Identity of this PC and Optional Password
        /// </summary>
        /// <param name="cipherText">The cipher text</param>
        /// <param name="password">The additional password your data is secured with</param>
        /// <returns></returns>
        public static string Decrypt(string cipherText, string password = "")
        {
            if (!Started) { Initialize(); }
            if (UniqueID == null) { throw new Exception("Must provide Identity"); }

            return Decrypt(cipherText, UniqueID, password);
        }

        /// <summary>
        /// Test the Identity_Strong key
        /// <para>If this matches the Identity key then you don't have a weak key</para>
        /// /// <param name="password">The additional password your data is secured with</param>
        /// </summary>
        /// <param name="strongIdentityKey"></param>
        /// <returns></returns>
        internal static bool CheckStrongID(string strongIdentityKey, string password = "")
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
            string strong_e = Encrypt(strong, strong.Substring(50), password);

            return strong_e == strongIdentityKey;
        }

        /// <summary>
        /// Creates a Unique Identity for this PC and stores it in the local Registry
        /// <para>If your identity key matches the strong key, Your identity is strong</para>
        /// <para>If your identity key matches the weak key, Your identity is weak</para>
        /// <param name="useStrongIdentity">True if strong identity should be used, strong identity doesn't change if the user deletes the keys</param>
        /// <param name="password">The additional password your data is to be secured with</param>
        /// </summary>
        internal static void GetNewMachineID(bool useStrongIdentity = true, string password = "")
        {
            string MotherboardUUID = (string)Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig", "LastConfig", "");

            if (!string.IsNullOrEmpty(MotherboardUUID)) { UUID = true; }

            byte[] WindowsAKIHash = (byte[])Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TPM\WMI", "WindowsAIKHash", "");

            string builder = "";
            if (WindowsAKIHash != null && WindowsAKIHash.Length > 0)
            {
                foreach (byte k in WindowsAKIHash)
                {
                    builder += k.ToString();
                }
                Hash = true;
            }

            string weakOne = Guid.NewGuid().ToString();
            string weakTwo = Guid.NewGuid().ToString();

            string finalUniqueWeak = ("F" + weakOne + "-" + "F" + weakTwo);
            string finalUniqueIDStrong = builder + "-" + MotherboardUUID;
            string finalUniqueID = (builder != "" ? builder : "F" + weakOne) + "-" + (MotherboardUUID != "" ? MotherboardUUID : "F" + weakTwo);

            bool isStrong = finalUniqueID == finalUniqueIDStrong;

            string half = finalUniqueID.Substring(50); 

            if (!isStrong && useStrongIdentity) { throw new Exception("Identity is Weak"); }

            UniqueID = finalUniqueID;

            string e_string = Encrypt(finalUniqueID, half, password);
            string e_string_weak = Encrypt(finalUniqueWeak, half, password);
            string e_string_strong = Encrypt(finalUniqueIDStrong, half, password);

            Registry.SetValue(Path, "Identity", e_string);
            Registry.SetValue(Path, "Identity_Weak", e_string_weak);
            Registry.SetValue(Path, "Identity_Strong", e_string_strong);

            string debug = UUID.ToString() + "," + Hash.ToString() + "," + isStrong.ToString();
            Registry.SetValue(Path, "Debug", debug);
        }

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

        internal static string Decrypt(string c, string k, string p)
        {
            c = c.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(c);
            using (Aes encryptor = Aes.Create())
            {
                string b = k + p;
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(b, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });

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
                    c = Encoding.Unicode.GetString(ms.ToArray());
                };
            }
            return c;
        }
    }
}