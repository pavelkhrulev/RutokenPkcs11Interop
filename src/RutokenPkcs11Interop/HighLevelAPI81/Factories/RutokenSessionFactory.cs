using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

namespace Net.RutokenPkcs11Interop.HighLevelAPI81.Factories
{
    /// <summary>
    /// Factory for creation of ISession instances
    /// </summary>
    public class RutokenSessionFactory : ISessionFactory
    {
        /// <summary>
        /// Initializes session with specified handle
        /// </summary>
        /// <param name="factories">Factories to be used by Developer and Pkcs11Interop library</param>
        /// <param name="pkcs11Library">Low level PKCS#11 wrapper</param>
        /// <param name="sessionId">PKCS#11 handle of session</param>
        public ISession Create(Pkcs11InteropFactories factories, LowLevelPkcs11Library pkcs11Library, ulong sessionId)
        {
            LowLevelAPI81.RutokenPkcs11Library p11 = pkcs11Library as LowLevelAPI81.RutokenPkcs11Library;
            if (p11 == null)
                throw new ArgumentException("Incorrect type of low level PKCS#11 wrapper");

            return new RutokenSession(factories, p11, sessionId);
        }
    }
}
