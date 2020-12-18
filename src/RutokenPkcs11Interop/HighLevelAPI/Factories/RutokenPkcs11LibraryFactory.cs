using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;


namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{
    public class RutokenPkcs11LibraryFactory : IRutokenPkcs11LibraryFactory
    {

        private IPkcs11LibraryFactory _factory = null;

        public RutokenPkcs11LibraryFactory()
        {
            if (Platform.NativeULongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI40.Factories.RutokenPkcs11LibraryFactory();
                else
                    _factory = new HighLevelAPI41.Factories.RutokenPkcs11LibraryFactory();
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI80.Factories.RutokenPkcs11LibraryFactory();
                else
                    _factory = new HighLevelAPI81.Factories.RutokenPkcs11LibraryFactory();
            }
        }

        public IPkcs11Library LoadPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType)
        {
            return _factory.LoadPkcs11Library(factories, libraryPath, appType);
        }

        public IPkcs11Library LoadPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType, InitType initType)
        {
            return _factory.LoadPkcs11Library(factories, libraryPath, appType, initType);
        }

        public IRutokenPkcs11Library LoadRutokenPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType)
        {
            return (IRutokenPkcs11Library) LoadPkcs11Library(factories, libraryPath, appType);
        }

        public IRutokenPkcs11Library LoadRutokenPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType, InitType initType)
        {
            return (IRutokenPkcs11Library)LoadPkcs11Library(factories, libraryPath, appType, initType);
        }
    }
}
