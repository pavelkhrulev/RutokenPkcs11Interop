using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI80;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11Interop.HighLevelAPI80
{
    public class VolumeFormatInfoExtended : VolumeInfo, IVolumeFormatInfoExtended
    {
        internal CK_VOLUME_FORMAT_INFO_EXTENDED CkVolumeFormatInfoExtended { get; }

        public VolumeFormatInfoExtended(ulong volumeSize, FlashAccessMode accessMode,
            CKU volumeOwner, ulong flags)
        {
            CkVolumeFormatInfoExtended = new CK_VOLUME_FORMAT_INFO_EXTENDED()
            {
                VolumeSize = volumeSize,
                AccessMode = (ulong) accessMode,
                VolumeOwner = (ulong) volumeOwner,
                Flags = flags
            };
        }
    }
}
