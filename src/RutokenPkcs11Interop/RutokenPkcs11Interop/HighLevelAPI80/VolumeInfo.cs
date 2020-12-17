﻿using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI80
{
    public abstract class VolumeInfo
    {
        protected ulong _volumeSize;

        protected FlashAccessMode _accessMode;

        protected CKU _volumeOwner;

        protected ulong _flags;

        public ulong VolumeSize
        {
            get
            {
                return _volumeSize;
            }
        }

        public FlashAccessMode AccessMode
        {
            get
            {
                return _accessMode;
            }
        }

        public CKU VolumeOwner
        {
            get
            {
                return _volumeOwner;
            }
        }

        public ulong Flags
        {
            get
            {
                return _flags;
            }
        }
    }
}
