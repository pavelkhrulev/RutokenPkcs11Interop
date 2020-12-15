using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI40;
using Net.Pkcs11Interop.HighLevelAPI;

using RutokenPkcs11Interop.HighLevelAPI;
using LLA = RutokenPkcs11Interop.LowLevelAPI40;

namespace RutokenPkcs11Interop.HighLevelAPI40
{
    public class Pkcs11LibraryExtensions: Pkcs11Library, IPkcs11LibraryExtensions
    {
        protected Pkcs11LibraryExtensions(Pkcs11InteropFactories factories, string libraryPath)
            : base(factories, libraryPath)
        {

        }

        public Pkcs11LibraryExtensions(Pkcs11InteropFactories factories, string libraryPath, AppType appType)
            : base(factories, libraryPath, appType)
        {

        }

        public Pkcs11LibraryExtensions(Pkcs11InteropFactories factories, string libraryPath, AppType appType, InitType initType)
            : base(factories, libraryPath, appType, initType)
        {

        }

        public void FreeBuffer(IntPtr buffer)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            CKR rv = _pkcs11Library.C_EX_FreeBuffer(buffer);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
        }
    }
}
