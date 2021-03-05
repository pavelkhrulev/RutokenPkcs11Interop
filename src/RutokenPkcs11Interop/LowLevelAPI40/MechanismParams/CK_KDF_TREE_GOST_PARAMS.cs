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
    public struct CK_KDF_TREE_GOST_PARAMS
    {
        public NativeULong ulLabelLength;

        public IntPtr pLabel;

        public NativeULong ulSeedLength;

        public IntPtr pSeed;

        public NativeULong ulR;

        public NativeULong ulL;

        public NativeULong ulOffset;
    }
}
