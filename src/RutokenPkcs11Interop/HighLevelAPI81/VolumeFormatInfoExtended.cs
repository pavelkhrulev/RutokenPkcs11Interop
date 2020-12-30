using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI81;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11Interop.HighLevelAPI81
{
    public class VolumeFormatInfoExtended : IVolumeFormatInfoExtended
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
