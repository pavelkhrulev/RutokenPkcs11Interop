using System;
using System.Runtime.InteropServices;

using NativeULong = System.UInt32;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI40.MechanismParams
{
    /// <summary>
    /// Structure that provides the parameters to the CK_KDF_TREE_GOST_PARAMS mechanism
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_VENDOR_GOST_KEG_PARAMS
    {
        public IntPtr pPublicData;

        public NativeULong ulPublicDataLen;

        public IntPtr pUKM;

        public NativeULong ulUKMLen;
    }
}
