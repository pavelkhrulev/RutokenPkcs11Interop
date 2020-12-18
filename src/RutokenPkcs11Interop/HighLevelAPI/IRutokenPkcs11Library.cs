using System;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11Interop.HighLevelAPI
{
    public interface IRutokenPkcs11Library: IPkcs11Library
    {
        void FreeBuffer(IntPtr buffer);
    }
}
