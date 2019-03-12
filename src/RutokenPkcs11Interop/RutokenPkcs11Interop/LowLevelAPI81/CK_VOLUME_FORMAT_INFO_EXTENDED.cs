using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.LowLevelAPI81
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_FORMAT_INFO_EXTENDED
    {
        public ulong VolumeSize;

        public FlashAccessMode AccessMode;

        public CKU VolumeOwner;

        public ulong Flags;
    }
}
