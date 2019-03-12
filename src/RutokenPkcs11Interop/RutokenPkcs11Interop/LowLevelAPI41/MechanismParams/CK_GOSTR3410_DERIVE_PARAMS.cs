using System;
using System.Runtime.InteropServices;

namespace RutokenPkcs11Interop.LowLevelAPI41.MechanismParams
{
    /// <summary>
    /// Structure that provides the parameters to the CKM_GOSTR3410_DERIVE mechanism
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_GOSTR3410_DERIVE_PARAMS
    {
        /// <summary>
        /// Additional key diversification algorithm (CKD)
        /// </summary>
        public uint Kdf;

        /// <summary>
        /// Pointer to data with public key of a receiver
        /// </summary>
        public IntPtr PublicData;

        /// <summary>
        /// Length of data with public key of a receiver. Must be 64.
        /// </summary>
        public uint PublicDataLen;

        /// <summary>
        /// Pointer to a UKM data
        /// </summary>
        public IntPtr UKM;

        /// <summary>
        /// Length of UKM data in bytes. Must be 8.
        /// </summary>
        public uint UKMLen;
    }
}
