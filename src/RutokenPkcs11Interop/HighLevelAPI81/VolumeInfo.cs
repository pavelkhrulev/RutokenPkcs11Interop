using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.HighLevelAPI81
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
