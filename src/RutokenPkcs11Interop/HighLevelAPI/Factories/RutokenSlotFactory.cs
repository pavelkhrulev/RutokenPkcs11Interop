using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

// Note: Code in this file is maintained manually.

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Factory for creation of ISlot instances
    /// </summary>
    public class RutokenSlotFactory : IRutokenSlotFactory
    {
        /// <summary>
        /// Platform specific factory for creation of ISlot instances
        /// </summary>
        private ISlotFactory _factory = null;

        /// <summary>
        /// Initializes a new instance of the MockSlotFactory class
        /// </summary>
        public RutokenSlotFactory()
        {
            if (Platform.NativeULongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI40.Factories.RutokenSlotFactory();
                else
                    _factory = new HighLevelAPI41.Factories.RutokenSlotFactory();
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI80.Factories.RutokenSlotFactory();
                else
                    _factory = new HighLevelAPI81.Factories.RutokenSlotFactory();
            }
        }

        public ISlot Create(Pkcs11InteropFactories factories, LowLevelPkcs11Library pkcs11Library, ulong slotId)
        {
            return _factory.Create(factories, pkcs11Library, slotId);
        }

        public IRutokenSlot CreateRutoken(Pkcs11InteropFactories factories, LowLevelPkcs11Library pkcs11Library, ulong slotId)
        {
            return (IRutokenSlot) Create(factories, pkcs11Library, slotId);
        }
    }
}
