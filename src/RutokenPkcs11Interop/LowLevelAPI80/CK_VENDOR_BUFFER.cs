using System;
using System.Runtime.InteropServices;

using NativeULong = System.UInt64;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI80
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
        public NativeULong Size;
    }
}
