using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI41;
using HLA41 = Net.Pkcs11Interop.HighLevelAPI41;

namespace RutokenPkcs11Interop.HighLevelAPI41
{
    public static class Pkcs11Extensions
    {
        public static void FreeBuffer(this HLA41.Pkcs11 pkcs11, IntPtr buffer)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            CKR rv = pkcs11.LowLevelPkcs11.C_EX_FreeBuffer(buffer);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
        }
    }
}
