﻿using System.Runtime.InteropServices;

namespace RutokenPkcs11Interop.LowLevelAPI41
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_VOLUME_INFO_EXTENDED
    {
        public uint VolumeId;

        public uint VolumeSize;

        public uint AccessMode;

        public uint VolumeOwner;

        public uint Flags;
    }
}
