using System.Runtime.InteropServices;

namespace Net.RutokenPkcs11Interop.LowLevelAPI40
{
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_FORMAT_INFO_EXTENDED
    {
        public uint VolumeSize;

        public uint AccessMode;

        public uint VolumeOwner;

        public uint Flags;
    }
}
