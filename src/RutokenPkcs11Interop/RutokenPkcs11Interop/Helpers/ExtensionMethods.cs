using System;
using System.Collections.Generic;

namespace RutokenPkcs11Interop.Helpers
{
    public static class ExtensionMethods
    {
        public static byte[] Xor(this byte[] array1, byte[] array2)
        {
            if (array1.Length != array2.Length)
                throw new InvalidOperationException(
                    "Input arrays must have the same length.");

            byte[] result = new byte[array1.Length];
            for (var i = 0; i < array1.Length; i++)
            {
                result[i] = (byte)(array1[i] ^ array2[i]);
            }

            return result;
        }

        public static IEnumerable<string> SplitInParts(this string s, int partLength)
        {
            if (s == null)
                throw new ArgumentNullException("s");
            if (partLength <= 0)
                throw new ArgumentException();

            for (var i = 0; i < s.Length; i += partLength)
                yield return s.Substring(i, Math.Min(partLength, s.Length - i));
        }
    }
}
