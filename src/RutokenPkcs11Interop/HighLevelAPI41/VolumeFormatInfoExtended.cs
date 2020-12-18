using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI41;
using RutokenPkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11Interop.HighLevelAPI41
{
    public class VolumeFormatInfoExtended : VolumeInfo, IVolumeFormatInfoExtended
    {
        internal CK_VOLUME_FORMAT_INFO_EXTENDED CkVolumeFormatInfoExtended { get; }

        public VolumeFormatInfoExtended(uint volumeSize, FlashAccessMode accessMode,
            CKU volumeOwner, uint flags)
        {
            CkVolumeFormatInfoExtended = new CK_VOLUME_FORMAT_INFO_EXTENDED
            {
                VolumeSize = volumeSize,
                AccessMode = (uint) accessMode,
                VolumeOwner = (uint) volumeOwner,
                Flags = flags
            };
        }
    }
}
