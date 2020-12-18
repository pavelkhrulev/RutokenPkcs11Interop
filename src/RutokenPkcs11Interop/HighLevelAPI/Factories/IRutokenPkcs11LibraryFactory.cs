using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

namespace RutokenPkcs11Interop.HighLevelAPI.Factories
{

    public interface IRutokenPkcs11LibraryFactory : IPkcs11LibraryFactory
    {
        IRutokenPkcs11Library LoadRutokenPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType);

        IRutokenPkcs11Library LoadRutokenPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType, InitType initType);
    }
}
