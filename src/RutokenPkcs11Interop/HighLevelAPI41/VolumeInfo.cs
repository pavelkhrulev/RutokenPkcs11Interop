using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.LowLevelAPI41;

namespace Net.RutokenPkcs11Interop.HighLevelAPI41
{
    public class VolumeInfo : IVolumeInfo
    {
        protected uint _volumeSize;

        protected FlashAccessMode _accessMode;

        protected CKU _volumeOwner;

        protected uint _flags;

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

        public VolumeInfo(uint _volumeSize, FlashAccessMode _accessMode, CKU _volumeOwner, uint _flags)
        {
            this._volumeSize = _volumeSize;
            this._accessMode = _accessMode;
            this._volumeOwner = _volumeOwner;
            this._flags = _flags;
        }
    }
}
