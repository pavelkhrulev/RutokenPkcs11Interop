using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using RutokenPkcs11Interop.HighLevelAPI.Factories;
using RutokenPkcs11Interop.HighLevelAPI.MechanismParams;
using RutokenPkcs11Interop.HighLevelAPI81.MechanismParams;

// Note: Code in this file is maintained manually.

namespace RutokenPkcs11Interop.HighLevelAPI81.Factories
{
    /// <summary>
    /// Factory for creation of ISession instances
    /// </summary>
    public class RutokenMechanismParamsFactory : MechanismParamsFactory, IRutokenMechanismParamsFactory
    {
        public ICkGostR3410_12_256_DeriveParams CreateCkGostR3410_12_256_DeriveParams(ulong kdf, byte[] publicData, byte[] ukm)
        {
            return new CkGostR3410_12_256_DeriveParams(kdf, publicData, ukm);
        }

        public ICkGostR3410_12_DeriveParams CreateCkGostR3410_12_DeriveParams(ulong kdf, byte[] publicData, byte[] ukm)
        {
            return new CkGostR3410_12_DeriveParams(kdf, publicData, ukm);
        }
    }
}
