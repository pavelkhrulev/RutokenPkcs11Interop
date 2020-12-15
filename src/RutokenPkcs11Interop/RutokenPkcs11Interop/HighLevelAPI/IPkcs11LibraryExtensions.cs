using System;
using Net.Pkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public interface IPkcs11LibraryExtensions: IPkcs11Library
    {
        void FreeBuffer(IntPtr buffer);
    }
}
