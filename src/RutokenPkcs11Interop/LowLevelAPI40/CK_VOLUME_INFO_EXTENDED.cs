using System.Runtime.InteropServices;
using NativeULong = System.UInt32;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI40
{
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_INFO_EXTENDED
    {
        public NativeULong VolumeId;

        public NativeULong VolumeSize;

        public NativeULong AccessMode;

        public NativeULong VolumeOwner;

        public NativeULong Flags;
    }
}
