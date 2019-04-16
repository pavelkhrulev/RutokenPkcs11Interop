using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.LowLevelAPI40
{
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_INFO_EXTENDED
    {
        public uint VolumeId;

        public uint VolumeSize;

        public FlashAccessMode AccessMode;

        public CKU VolumeOwner;

        public uint Flags;
    }
}
