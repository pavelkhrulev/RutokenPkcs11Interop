using System.Collections.Generic;

using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

// Note: Code in this file is maintained manually.

namespace RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Developer rarely uses this factory to create correct IObjectHandle instances.
    /// </summary>
    public class VolumeFormatInfoExtendedFactory : IVolumeFormatInfoExtendedFactory
    {
        /// <summary>
        /// Platform specific factory for creation of IObjectHandle instances
        /// </summary>
        private IVolumeFormatInfoExtendedFactory _factory = null;

        /// <summary>
        /// Initializes a new instance of the ObjectHandleFactory class
        /// </summary>
        public VolumeFormatInfoExtendedFactory()
        {
            if (Platform.NativeULongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI40.Factories.VolumeFormatInfoExtendedFactory();
                else
                    _factory = new HighLevelAPI41.Factories.VolumeFormatInfoExtendedFactory();
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI80.Factories.VolumeFormatInfoExtendedFactory();
                else
                    _factory = new HighLevelAPI81.Factories.VolumeFormatInfoExtendedFactory();
            }
        }

        public IVolumeFormatInfoExtended Create(ulong volumeSize, FlashAccessMode accessMode,
            CKU volumeOwner, ulong flags)
        {
            return _factory.Create(volumeSize, accessMode, volumeOwner, flags);
        }
    }
}
