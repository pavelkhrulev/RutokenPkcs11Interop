﻿using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.LowLevelAPI81;

namespace Net.RutokenPkcs11Interop.HighLevelAPI81
{
    public class VolumeInfo : IVolumeInfo
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

        public VolumeInfo(ulong _volumeSize, FlashAccessMode _accessMode, CKU _volumeOwner, ulong _flags)
        {
            this._volumeSize = _volumeSize;
            this._accessMode = _accessMode;
            this._volumeOwner = _volumeOwner;
            this._flags = _flags;
        }
    }
}
