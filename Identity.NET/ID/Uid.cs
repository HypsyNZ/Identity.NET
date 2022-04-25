using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;

namespace Identity.NET.Id
{
    internal static class Uid
    {
        internal static string UniqueID = null;

        internal static string Initialize(bool useStrongIdentity = true, string pathToIdentity = "", string password = "", bool allowMixed = true)
        {
            Machine.Path = pathToIdentity;

            string ID = Registry.GetValue(Machine.Path, "Identity", "") as string;
            string IDW = Registry.GetValue(Machine.Path, "Identity_Weak", "") as string;
            string IDS = Registry.GetValue(Machine.Path, "Identity_Strong", "") as string;

            if (string.IsNullOrEmpty(ID) || string.IsNullOrEmpty(IDS) || string.IsNullOrEmpty(IDW))
            {
                UniqueID = Machine.GetNewMachineID(useStrongIdentity, password, allowMixed);
            }
            else
            {
                if (ID != IDS && useStrongIdentity)
                {
                    throw new Exception("Identity is Weak");
                }

                if (useStrongIdentity)
                {
                    if (!Check.StrongID(IDS, password))
                    {
                        throw new Exception("Identity Is Weak");
                    };
                }

                string half = ID.Substring(50);
                if (!string.IsNullOrEmpty(half))
                {
                    UniqueID = Crypt.Decrypt(ID, half, password);
                    return UniqueID;
                }
            }

            return null;
        }
    }
}
