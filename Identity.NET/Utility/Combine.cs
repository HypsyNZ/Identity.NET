using System;
using System.Collections.Generic;
using System.Text;

namespace Identity.NET.Utility
{
    internal class Combine
    {
        public static byte[] ByteArray(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }
    }
}
