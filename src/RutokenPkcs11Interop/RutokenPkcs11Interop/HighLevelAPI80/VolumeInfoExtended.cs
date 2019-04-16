using RutokenPkcs11Interop.LowLevelAPI80;

namespace RutokenPkcs11Interop.HighLevelAPI80
{
    public class VolumeInfoExtended : VolumeInfo
    {
        public ulong VolumeId { get; }

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
