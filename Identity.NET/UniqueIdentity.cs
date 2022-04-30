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

using Identity.NET.Id;
using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

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
        /// <param name="allowMixed">Allow the use of mixed keys when using Weak Keys (Recommended)</param>
        /// <exception cref="Exception">Throws when identity is weak</exception>
        /// <exception cref="ArgumentException">Throws when you try to edit the default identity</exception>
        /// <returns>Bool Indicating if the ID is Initialized</returns>
        public static bool Initialize(bool useStrongIdentity = true, string pathToIdentity = @"HKEY_LOCAL_MACHINE\SOFTWARE\Identity.NET", string password = "Identity.NET", bool allowMixed = true)
        {
            if(pathToIdentity.Contains(@"SOFTWARE\Identity.NET") && password != "Identity.NET")
            {
                throw new ArgumentException("You can't edit the default Identity, Set pathToIdentity if you want to use a different password");
            }

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
            return Crypt.Encrypt(clearText, Uid.UniqueID, password, Machine.Path);
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
            return Crypt.Decrypt(cipherText, Uid.UniqueID, password, Machine.Path);
        }
    }
}
