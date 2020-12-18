using System;
using System.IO;
using System.Linq;

namespace Net.RutokenPkcs11Interop.Helpers
{
    public static class ISO_10126_Padding
    {
        public static byte[] Pad(byte[] data, int blockSize)
        {
            var paddingSize = blockSize - data.Length % blockSize;
            using (var ms = new MemoryStream())
            {
                ms.Write(data, 0, data.Length);
                var random = new Random();
                var padding = new byte[paddingSize - 1];
                random.NextBytes(padding);
                ms.Write(padding, 0, padding.Length);
                ms.WriteByte((byte)paddingSize);

                return ms.ToArray();
            }
        }

        public static byte[] Unpad(byte[] data)
        {
            return data.Take(data.Length - data[data.Length - 1]).ToArray();
        }
    }
}
