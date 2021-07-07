using System;
using System.Runtime.InteropServices;

using NativeULong = System.UInt64;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI80.MechanismParams
{
    /// <summary>
    /// Structure that provides the parameters to the CK_KDF_TREE_GOST_PARAMS mechanism
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_VENDOR_VKO_GOSTR3410_2012_512_PARAMS
    {
        public NativeULong kdf;
        public IntPtr pPublicData;
        public NativeULong ulPublicDataLen;
        public IntPtr pUKM;
        public NativeULong ulUKMLen;
    }
}
