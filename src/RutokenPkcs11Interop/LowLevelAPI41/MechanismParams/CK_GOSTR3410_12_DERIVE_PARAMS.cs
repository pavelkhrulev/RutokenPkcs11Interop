using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace RutokenPkcs11Interop.LowLevelAPI41.MechanismParams
{
    /// <summary>
    /// Structure that provides the parameters to the CKM_GOSTR3410_DERIVE mechanism
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_GOSTR3410_12_DERIVE_PARAMS
    {
        /// <summary>
        /// Additional key diversification algorithm (CKD)
        /// </summary>
        public uint Kdf;

        /// <summary>
        /// Length of data with public key of a receiver. Must be 64.
        /// </summary>
        public uint PublicDataLen;

        /// <summary>
        /// Pointer to data with public key of a receiver
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
        public byte[] PublicData;

        /// <summary>
        /// Length of UKM data in bytes. Must be 8.
        /// </summary>
        public uint UKMLen;

        /// <summary>
        /// Pointer to a UKM data
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] UKM;
    }
}
