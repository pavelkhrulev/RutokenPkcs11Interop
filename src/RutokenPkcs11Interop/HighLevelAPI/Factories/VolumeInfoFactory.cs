using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;

// Note: Code in this file is maintained manually.

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Factory for creation of ISlot instances
    /// </summary>
    public class VolumeInfoFactory : IVolumeInfoFactory
    {
        /// <summary>
        /// Platform specific factory for creation of ISlot instances
        /// </summary>
        private IVolumeInfoFactory _factory = null;

        /// <summary>
        /// Initializes a new instance of the MockSlotFactory class
        /// </summary>
        public VolumeInfoFactory()
        {
            if (Platform.NativeULongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI40.Factories.VolumeInfoFactory();
                else
                    _factory = new HighLevelAPI41.Factories.VolumeInfoFactory();
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI80.Factories.VolumeInfoFactory();
                else
                    _factory = new HighLevelAPI81.Factories.VolumeInfoFactory();
            }
        }

        public IVolumeInfo Create(ulong VolumeSize, FlashAccessMode AccessMode, CKU VolumeOwner, ulong Flags)
        {
            return _factory.Create(VolumeSize, AccessMode, VolumeOwner, Flags);
        }
    }
}
