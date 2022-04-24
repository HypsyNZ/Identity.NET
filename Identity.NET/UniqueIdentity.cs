using Identity.NET.Id;
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
        internal static bool Started = false;

        /// <summary>
        /// The Unique Identifier for this PC
        /// </summary>
        public static string UUID => Uid.UniqueID;

        /// <summary>
        /// Initializes the Unique Identity for this PC
        /// </summary>
        /// <param name="useStrongIdentity">True if strong identity should be used, strong identity doesn't change if the user deletes the keys</param>
        /// <param name="pathToIdentity">The registry path for the identity</param>
        /// <param name="password">The additional password your data is secured with</param>
        /// <exception cref="Exception">Throws when identity is weak</exception>
        public static string Initialize(bool useStrongIdentity = true, string pathToIdentity = "", string password = "")
        {
            Started = true;
            return Uid.Initialize(useStrongIdentity, pathToIdentity, password);
        }

        /// <summary>
        /// Encrypt a string using the Unique Identity of this PC and Optional Password
        /// </summary>
        /// <param name="clearText">The plain text</param>
        /// <param name="password">The additional password your data is to be secured with</param>
        /// <returns></returns>
        public static string Encrypt(string clearText, string password = "")
        {
            if (Uid.UniqueID == null) { throw new ArgumentNullException("Must provide Identity First (Not Initialized)"); }
            return Crypt.Encrypt(clearText, Uid.UniqueID, password);
        }

        /// <summary>
        /// Decrypt a string using the Unique Identity of this PC and Optional Password
        /// </summary>
        /// <param name="cipherText">The cipher text</param>
        /// <param name="password">The additional password your data is secured with</param>
        /// <returns></returns>
        public static string Decrypt(string cipherText, string password = "")
        {
            if (Uid.UniqueID == null) { throw new ArgumentNullException("Must provide Identity First (Not Initialized)"); }
            return Crypt.Decrypt(cipherText, Uid.UniqueID, password);
        }
    }
}
