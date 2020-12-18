using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

// Note: Code in this file is maintained manually.

namespace RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Factory for creation of ISession instances
    /// </summary>
    public class RutokenSessionFactory : IRutokenSessionFactory
    {
        /// <summary>
        /// Platform specific factory for creation of ISession instances
        /// </summary>
        private ISessionFactory _factory = null;

        /// <summary>
        /// Initializes a new instance of the MockSessionFactory class
        /// </summary>
        public RutokenSessionFactory()
        {
            if (Platform.NativeULongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI40.Factories.RutokenSessionFactory();
                else
                    _factory = new HighLevelAPI41.Factories.RutokenSessionFactory();
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI80.Factories.RutokenSessionFactory();
                else
                    _factory = new HighLevelAPI81.Factories.RutokenSessionFactory();
            }
        }

        /// <summary>
        /// Initializes session with specified handle
        /// </summary>
        /// <param name="factories">Factories to be used by Developer and Pkcs11Interop library</param>
        /// <param name="pkcs11Library">Low level PKCS#11 wrapper</param>
        /// <param name="sessionId">PKCS#11 handle of session</param>
        public ISession Create(Pkcs11InteropFactories factories, LowLevelPkcs11Library pkcs11Library, ulong sessionId)
        {
            return _factory.Create(factories, pkcs11Library, sessionId);
        }

        public IRutokenSession CreateRutoken(Pkcs11InteropFactories factories, LowLevelPkcs11Library pkcs11Library, ulong sessionId)
        {
            return (IRutokenSession) Create(factories, pkcs11Library, sessionId);
        }
    }
}
