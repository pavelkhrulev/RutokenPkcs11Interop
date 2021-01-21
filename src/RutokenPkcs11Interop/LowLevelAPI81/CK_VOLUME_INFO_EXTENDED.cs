using System.Runtime.InteropServices;
using NativeULong = System.UInt64;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI81
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_INFO_EXTENDED
    {
        public NativeULong VolumeId;

        public NativeULong VolumeSize;

        public NativeULong AccessMode;

        public NativeULong VolumeOwner;

        public NativeULong Flags;
    }
}
