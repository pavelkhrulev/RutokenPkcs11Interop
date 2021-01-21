using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI40;
using Net.RutokenPkcs11Interop.HighLevelAPI;

using NativeULong = System.UInt32;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.HighLevelAPI40
{
    public class VolumeFormatInfoExtended : IVolumeFormatInfoExtended
    {
        internal CK_VOLUME_FORMAT_INFO_EXTENDED CkVolumeFormatInfoExtended { get; }

        public VolumeFormatInfoExtended(ulong volumeSize, FlashAccessMode accessMode,
            CKU volumeOwner, ulong flags)
        {
            CkVolumeFormatInfoExtended = new CK_VOLUME_FORMAT_INFO_EXTENDED
            {
                VolumeSize = (NativeULong) volumeSize,
                AccessMode = (NativeULong) accessMode,
                VolumeOwner = (NativeULong) volumeOwner,
                Flags = (NativeULong) flags
            };
        }
    }
}
