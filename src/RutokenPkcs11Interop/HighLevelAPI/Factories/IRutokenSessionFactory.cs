using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

// Note: Code in this file is maintained manually.

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Factory for creation of ISession instances
    /// </summary>
    public interface IRutokenSessionFactory : ISessionFactory
    {
        IRutokenSession CreateRutoken(Pkcs11InteropFactories factories, LowLevelPkcs11Library pkcs11Library, ulong sessionId);
    }
}
