using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI80;
using RutokenPkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11Interop.HighLevelAPI80
{
    public class VolumeInfoExtended : VolumeInfo, IVolumeInfoExtended
    {
        protected ulong _volumeId;
        public ulong VolumeId
        {
            get
            {
                return _volumeId;
            }
        }

        internal VolumeInfoExtended(CK_VOLUME_INFO_EXTENDED ckVolumeInfoExtended)
        {
            _volumeId = ckVolumeInfoExtended.VolumeId;
            _volumeSize = ckVolumeInfoExtended.VolumeSize;
            _accessMode = (FlashAccessMode)ckVolumeInfoExtended.AccessMode;
            _volumeOwner = (CKU)ckVolumeInfoExtended.VolumeOwner;
            _flags = ckVolumeInfoExtended.Flags;
        }
    }
}
