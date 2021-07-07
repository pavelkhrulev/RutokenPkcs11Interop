using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;

// Note: Code in this file is maintained manually.

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Factory for creation of ISlot instances
    /// </summary>
    public class VolumeInfoExtendedFactory : IVolumeInfoExtendedFactory
    {
        /// <summary>
        /// Platform specific factory for creation of ISlot instances
        /// </summary>
        private IVolumeInfoExtendedFactory _factory = null;

        /// <summary>
        /// Initializes a new instance of the MockSlotFactory class
        /// </summary>
        public VolumeInfoExtendedFactory()
        {
            if (Platform.NativeULongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI40.Factories.VolumeInfoExtendedFactory();
                else
                    _factory = new HighLevelAPI41.Factories.VolumeInfoExtendedFactory();
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI80.Factories.VolumeInfoExtendedFactory();
                else
                    _factory = new HighLevelAPI81.Factories.VolumeInfoExtendedFactory();
            }
        }

        public IVolumeInfoExtended Create(ulong VolumeId, ulong VolumeSize, FlashAccessMode AccessMode, CKU VolumeOwner, ulong Flags)
        {
            return _factory.Create(VolumeId, VolumeSize, AccessMode, VolumeOwner, Flags);
        }
    }
}
