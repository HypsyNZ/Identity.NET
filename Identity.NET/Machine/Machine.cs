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
        /// <param name="allowMixed">Allow the use of mixed keys when using Weak Keys (True by default)</param>
        /// </summary>
        internal static IdentitySuccess GetNewMachineID(bool useStrongIdentity = true, string password = "", bool allowMixed = true)
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

            bool isStrong = finalUniqueIDStrong == finalUniqueID;
            bool isMixed = finalUniqueWeak == finalUniqueID ? false : finalUniqueIDStrong == finalUniqueID ? false : true;

            string half = finalUniqueID.Substring(50);

            // Don't write anything to the identity and cancel
            if (useStrongIdentity && !isStrong) { return new IdentitySuccess(false, null); }
            if (!useStrongIdentity && isMixed && !allowMixed) { return new IdentitySuccess(false, null); }

            string e_string = Crypt.Encrypt(finalUniqueID, half, password);
            string e_string_weak = Crypt.Encrypt(finalUniqueWeak, half, password);
            string e_string_strong = Crypt.Encrypt(finalUniqueIDStrong, half, password);
            string debug = UUID.ToString() + "," + Hash.ToString() + ",Mixed:" + isMixed.ToString();

            Registry.SetValue(Path, "Identity", e_string);
            Registry.SetValue(Path, "Identity_Weak", e_string_weak);
            Registry.SetValue(Path, "Identity_Strong", e_string_strong);
            Registry.SetValue(Path, "Debug", debug);

            return new IdentitySuccess(true, e_string);
        }
    }
}
