using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI80;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11Interop.HighLevelAPI80
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

        internal VolumeInfoExtended(ulong volumeId, ulong volumeSize, FlashAccessMode accessMode, CKU volumeOwner, ulong flags)
    : base(volumeSize, accessMode, volumeOwner, flags)
        {
            _volumeId = volumeId;
        }

        internal VolumeInfoExtended(CK_VOLUME_INFO_EXTENDED ckVolumeInfoExtended)
            : base(ckVolumeInfoExtended.VolumeSize, (FlashAccessMode)ckVolumeInfoExtended.AccessMode, (CKU)ckVolumeInfoExtended.VolumeOwner, ckVolumeInfoExtended.Flags)
        {
            _volumeId = ckVolumeInfoExtended.VolumeId;
        }
    }
}
