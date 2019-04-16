using System;
using System.Runtime.InteropServices;

namespace RutokenPkcs11Interop.LowLevelAPI80
{
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_VENDOR_BUFFER
    {
        /// <summary>
        /// Pointer to data
        /// </summary>
        public IntPtr Data;

        /// <summary>
        /// Length of data
        /// </summary>
        public ulong Size;
    }
}
