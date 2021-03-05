using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using Net.RutokenPkcs11Interop.HighLevelAPI.MechanismParams;

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{

    public interface IRutokenMechanismParamsFactory : IMechanismParamsFactory
    {
        ICkGostR3410_12_256_DeriveParams CreateCkGostR3410_12_256_DeriveParams(ulong kdf, byte[] publicData, byte[] ukm);

        ICkGostR3410_12_DeriveParams CreateCkGostR3410_12_DeriveParams(ulong kdf, byte[] publicData, byte[] ukm);

        ICkKdfTreeGostParams CreateCkKdfTreeGostParams(byte[] label, byte[] seed, long r, long l, long offset);

        ICkVendorGostKegParams CreateCkVendorGostKegParams(byte[] publicData, byte[] ukm);

        ICkVendorVkoGostR3410_2012_512Params CreateCkVendorVkoGostR3410_2012_512Params(ulong kdf, byte[] publicData, byte[] ukm);
    }
}
