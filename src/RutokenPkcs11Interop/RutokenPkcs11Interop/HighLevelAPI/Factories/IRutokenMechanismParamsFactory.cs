using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using RutokenPkcs11Interop.HighLevelAPI.MechanismParams;

namespace RutokenPkcs11Interop.HighLevelAPI.Factories
{

    public interface IRutokenMechanismParamsFactory : IMechanismParamsFactory
    {
        ICkGostR3410_12_256_DeriveParams CreateCkGostR3410_12_256_DeriveParams(ulong kdf, byte[] publicData, byte[] ukm);

        ICkGostR3410_12_DeriveParams CreateCkGostR3410_12_DeriveParams(ulong kdf, byte[] publicData, byte[] ukm);
    }
}
