using System.Runtime.InteropServices;
using NativeULong = System.UInt32;

// Note: Code in this file is maintained manually

namespace Net.RutokenPkcs11Interop.LowLevelAPI41
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_FORMAT_INFO_EXTENDED
    {
        public NativeULong VolumeSize;

        public NativeULong AccessMode;

        public NativeULong VolumeOwner;

        public NativeULong Flags;
    }
}
