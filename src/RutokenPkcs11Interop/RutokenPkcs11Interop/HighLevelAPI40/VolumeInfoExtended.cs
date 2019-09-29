using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI40;

namespace RutokenPkcs11Interop.HighLevelAPI40
{
    public class VolumeInfoExtended : VolumeInfo
    {
        public uint VolumeId { get; }

        internal VolumeInfoExtended(CK_VOLUME_INFO_EXTENDED ckVolumeInfoExtended)
        {
            VolumeId = ckVolumeInfoExtended.VolumeId;
            VolumeSize = ckVolumeInfoExtended.VolumeSize;
            AccessMode = (FlashAccessMode) ckVolumeInfoExtended.AccessMode;
            VolumeOwner = (CKU) ckVolumeInfoExtended.VolumeOwner;
            Flags = ckVolumeInfoExtended.Flags;
        }
    }
}
