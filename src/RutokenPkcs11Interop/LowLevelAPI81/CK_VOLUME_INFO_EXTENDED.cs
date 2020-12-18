using System.Runtime.InteropServices;

namespace Net.RutokenPkcs11Interop.LowLevelAPI81
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_INFO_EXTENDED
    {
        public ulong VolumeId;

        public ulong VolumeSize;

        public ulong AccessMode;

        public ulong VolumeOwner;

        public ulong Flags;
    }
}
