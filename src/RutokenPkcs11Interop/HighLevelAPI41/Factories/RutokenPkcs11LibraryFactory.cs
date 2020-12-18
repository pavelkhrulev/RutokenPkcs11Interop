using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

namespace Net.RutokenPkcs11Interop.HighLevelAPI41.Factories
{
    /// <summary>
    /// Factory for creation of IPkcs11Library instances
    /// </summary>
    public class RutokenPkcs11LibraryFactory : IPkcs11LibraryFactory
    {
        /// <summary>
        /// Loads and initializes PCKS#11 library
        /// </summary>
        /// <param name="factories">Factories to be used by Developer and Pkcs11Interop library</param>
        /// <param name="libraryPath">Library name or path</param>
        /// <param name="appType">Type of application that will be using PKCS#11 library</param>
        /// <returns>High level PKCS#11 wrapper</returns>
        public IPkcs11Library LoadPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType)
        {
            return new RutokenPkcs11Library(factories, libraryPath, appType);
        }

        /// <summary>
        /// Loads and initializes PCKS#11 library
        /// </summary>
        /// <param name="factories">Factories to be used by Developer and Pkcs11Interop library</param>
        /// <param name="libraryPath">Library name or path</param>
        /// <param name="appType">Type of application that will be using PKCS#11 library</param>
        /// <param name="initType">Source of PKCS#11 function pointers</param>
        /// <returns>High level PKCS#11 wrapper</returns>
        public IPkcs11Library LoadPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType, InitType initType)
        {
            return new RutokenPkcs11Library(factories, libraryPath, appType, initType);
        }
    }
}
