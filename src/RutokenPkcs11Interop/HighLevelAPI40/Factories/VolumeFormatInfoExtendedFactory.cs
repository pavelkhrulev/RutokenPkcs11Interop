using System.Collections.Generic;

using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI.Factories;
using Net.RutokenPkcs11Interop.HighLevelAPI;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.HighLevelAPI40.Factories
{
    /// <summary>
    /// Developer rarely uses this factory to create correct IObjectHandle instances.
    /// </summary>
    public class VolumeFormatInfoExtendedFactory : IVolumeFormatInfoExtendedFactory
    {
        public IVolumeFormatInfoExtended Create(ulong volumeSize, FlashAccessMode accessMode,
            CKU volumeOwner, ulong flags)
        {
            return new VolumeFormatInfoExtended(volumeSize, accessMode, volumeOwner, flags);
        }
    }
}
