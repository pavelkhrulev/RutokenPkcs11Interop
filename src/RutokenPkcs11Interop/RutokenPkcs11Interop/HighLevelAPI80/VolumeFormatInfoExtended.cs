using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI80;

namespace RutokenPkcs11Interop.HighLevelAPI80
{
    public class VolumeFormatInfoExtended : VolumeInfo
    {
        internal CK_VOLUME_FORMAT_INFO_EXTENDED CkVolumeFormatInfoExtended { get; }

        public VolumeFormatInfoExtended(ulong volumeSize, FlashAccessMode accessMode,
            CKU volumeOwner, ulong flags)
        {
            CkVolumeFormatInfoExtended = new CK_VOLUME_FORMAT_INFO_EXTENDED()
            {
                VolumeSize = volumeSize,
                AccessMode = accessMode,
                VolumeOwner = volumeOwner,
                Flags = flags
            };
        }
    }
}
