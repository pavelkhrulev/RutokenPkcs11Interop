using System.Runtime.InteropServices;

namespace RutokenPkcs11Interop.LowLevelAPI80
{
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_INFO_EXTENDED
    {
        public ulong VolumeId;

        public ulong VolumeSize;

        public ulong AccessMode;

        public ulong VolumeOwner;

        public ulong Flags;
    }
}
