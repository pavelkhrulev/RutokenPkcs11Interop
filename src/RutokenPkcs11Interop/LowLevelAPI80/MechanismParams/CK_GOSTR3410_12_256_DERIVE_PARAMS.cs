using System.Runtime.InteropServices;

using NativeULong = System.UInt64;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI80.MechanismParams
{
    /// <summary>
    /// Structure that provides the parameters to the CKM_GOSTR3410_DERIVE mechanism
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_GOSTR3410_12_256_DERIVE_PARAMS
    {
        /// <summary>
        /// Additional key diversification algorithm (CKD)
        /// </summary>
        public NativeULong Kdf;

        /// <summary>
        /// Length of data with public key of a receiver. Must be 64.
        /// </summary>
        public NativeULong PublicDataLen;

        /// <summary>
        /// Pointer to data with public key of a receiver
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] PublicData;

        /// <summary>
        /// Length of UKM data in bytes. Must be 8.
        /// </summary>
        public NativeULong UKMLen;

        /// <summary>
        /// Pointer to a UKM data
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] UKM;
    }
}
