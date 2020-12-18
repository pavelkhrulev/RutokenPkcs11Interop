using System;
using System.Runtime.InteropServices;

namespace Net.RutokenPkcs11Interop.LowLevelAPI40
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
        public uint Size;
    }
}
