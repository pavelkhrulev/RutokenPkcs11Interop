using RutokenPkcs11Interop.LowLevelAPI41;

namespace RutokenPkcs11Interop.HighLevelAPI41
{
    public class VolumeInfoExtended : VolumeInfo
    {
        public uint VolumeId { get; }

        internal VolumeInfoExtended(CK_VOLUME_INFO_EXTENDED ckVolumeInfoExtended)
        {
            VolumeId = ckVolumeInfoExtended.VolumeId;
            VolumeSize = ckVolumeInfoExtended.VolumeSize;
            AccessMode = ckVolumeInfoExtended.AccessMode;
            VolumeOwner = ckVolumeInfoExtended.VolumeOwner;
            Flags = ckVolumeInfoExtended.Flags;
        }
    }
}
