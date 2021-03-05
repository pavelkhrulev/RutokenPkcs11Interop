using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;
using Net.RutokenPkcs11Interop.HighLevelAPI.MechanismParams;

// Note: Code in this file is maintained manually.

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Factory for creation of ISession instances
    /// </summary>
    public class RutokenMechanismParamsFactory : MechanismParamsFactory, IRutokenMechanismParamsFactory
    {
        IRutokenMechanismParamsFactory _factory = null;

        /// <summary>
        /// Initializes a new instance of the MockSessionFactory class
        /// </summary>
        public RutokenMechanismParamsFactory()
            : base()
        {
            if (Platform.NativeULongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI40.Factories.RutokenMechanismParamsFactory();
                else
                    _factory = new HighLevelAPI41.Factories.RutokenMechanismParamsFactory();
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI80.Factories.RutokenMechanismParamsFactory();
                else
                    _factory = new HighLevelAPI81.Factories.RutokenMechanismParamsFactory();
            }
        }

        public ICkGostR3410_12_256_DeriveParams CreateCkGostR3410_12_256_DeriveParams(ulong kdf, byte[] publicData, byte[] ukm)
        {
            return _factory.CreateCkGostR3410_12_256_DeriveParams(kdf, publicData, ukm);
        }

        public ICkGostR3410_12_DeriveParams CreateCkGostR3410_12_DeriveParams(ulong kdf, byte[] publicData, byte[] ukm)
        {
            return _factory.CreateCkGostR3410_12_DeriveParams(kdf, publicData, ukm);
        }

        public ICkKdfTreeGostParams CreateCkKdfTreeGostParams(byte[] label, byte[] seed, long r, long l, long offset)
        {
            return _factory.CreateCkKdfTreeGostParams(label, seed, r, l, offset);
        }

        public ICkVendorGostKegParams CreateCkVendorGostKegParams(byte[] publicData, byte[] ukm)
        {
            return _factory.CreateCkVendorGostKegParams(publicData, ukm);
        }

        public ICkVendorVkoGostR3410_2012_512Params CreateCkVendorVkoGostR3410_2012_512Params(ulong kdf, byte[] publicData, byte[] ukm)
        {
            return _factory.CreateCkVendorVkoGostR3410_2012_512Params(kdf, publicData, ukm);
        }
    }
}
