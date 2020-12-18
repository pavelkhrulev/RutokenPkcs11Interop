using System.Runtime.InteropServices;

namespace Net.RutokenPkcs11Interop.LowLevelAPI80
{
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_FORMAT_INFO_EXTENDED
    {
        public ulong VolumeSize;

        public ulong AccessMode;

        public ulong VolumeOwner;

        public ulong Flags;
    }
}
