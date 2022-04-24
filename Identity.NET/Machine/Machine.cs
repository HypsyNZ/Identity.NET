using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

namespace Identity.NET.Id
{
    internal class Machine
    {
        internal static bool UUID = false;
        internal static bool Hash = false;
        internal static bool Seed = false;
        internal static string Path = "";

        /// <summary>
        /// Creates a Unique Identity for this PC and stores it in the local Registry
        /// <para>If your identity key matches the strong key, Your identity is strong</para>
        /// <para>If your identity key matches the weak key, Your identity is weak</para>
        /// <param name="useStrongIdentity">True if strong identity should be used, strong identity doesn't change if the user deletes the keys</param>
        /// <param name="password">The additional password your data is to be secured with</param>
        /// </summary>
        internal static string GetNewMachineID(bool useStrongIdentity = true, string password = "")
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

            string e_string = Crypt.Encrypt(finalUniqueID, half, password);
            string e_string_weak = Crypt.Encrypt(finalUniqueWeak, half, password);
            string e_string_strong = Crypt.Encrypt(finalUniqueIDStrong, half, password);

            Registry.SetValue(Path, "Identity", e_string);
            Registry.SetValue(Path, "Identity_Weak", e_string_weak);
            Registry.SetValue(Path, "Identity_Strong", e_string_strong);

            string debug = UUID.ToString() + "," + Hash.ToString() + "," + isStrong.ToString();
            Registry.SetValue(Path, "Debug", debug);

            return finalUniqueID;
        }
    }
}
