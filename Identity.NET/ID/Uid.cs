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

namespace Identity.NET.Id
{
    internal static class Uid
    {
        internal static volatile string UniqueID = null;

        internal static bool Initialize(bool useStrongIdentity = true, string pathToIdentity = "", string password = "", bool allowMixed = true)
        {
            Machine.Path = pathToIdentity;

            string IDv2 = Registry.GetValue(Machine.Path, "IdentityV2", "") as string;
            string IDWv2 = Registry.GetValue(Machine.Path, "IdentityV2_Weak", "") as string;
            string IDSv2 = Registry.GetValue(Machine.Path, "IdentityV2_Strong", "") as string;

            if (string.IsNullOrWhiteSpace(IDv2) && string.IsNullOrWhiteSpace(IDWv2) && string.IsNullOrWhiteSpace(IDSv2))
            {
                IdentitySuccess success = Machine.GetNewMachineID(pathToIdentity, useStrongIdentity, password, allowMixed);
                if (success.Success == true)
                {
                    string half = success.Identity.Substring(50);
                    UniqueID = Crypt.Decrypt(success.Identity, half, password, Machine.Path);
                    return true;
                }

                return false;
            }
            else
            {
                if (IDv2 != IDSv2 && useStrongIdentity)
                {
                    throw new Exception("Identity is Weak");
                }

                if (useStrongIdentity)
                {
                    if (!Check.StrongID(IDSv2, password))
                    {
                        throw new Exception("Identity Is Weak");
                    };
                }

                string half = IDv2.Substring(50);
                if (!string.IsNullOrEmpty(half))
                {
                    UniqueID = Crypt.Decrypt(IDv2, half, password, pathToIdentity);
                    return true;
                }
            }

            return false;
        }
    }
}
