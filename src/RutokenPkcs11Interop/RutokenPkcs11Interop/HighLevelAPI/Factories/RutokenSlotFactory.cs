using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

// Note: Code in this file is maintained manually.

namespace RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Factory for creation of ISlot instances
    /// </summary>
    public class RutokenSlotFactory : ISlotFactory
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

        /// <summary>
        /// Creates slot with specified handle
        /// </summary>
        /// <param name="factories">Factories to be used by Developer and Pkcs11Interop library</param>
        /// <param name="pkcs11Library">Low level PKCS#11 wrapper</param>
        /// <param name="slotId">PKCS#11 handle of slot</param>
        public ISlot Create(Pkcs11InteropFactories factories, LowLevelPkcs11Library pkcs11Library, ulong slotId)
        {
            return _factory.Create(factories, pkcs11Library, slotId);
        }
    }
}
