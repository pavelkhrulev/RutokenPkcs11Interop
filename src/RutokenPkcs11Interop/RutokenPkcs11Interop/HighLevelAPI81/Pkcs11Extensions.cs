using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI81;
using HLA81 = Net.Pkcs11Interop.HighLevelAPI81;

namespace RutokenPkcs11Interop.HighLevelAPI81
{
    public static class Pkcs11Extensions
    {
        public static void FreeBuffer(this HLA81.Pkcs11 pkcs11, IntPtr buffer)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            CKR rv = pkcs11.LowLevelPkcs11.C_EX_FreeBuffer(buffer);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
        }
    }
}
