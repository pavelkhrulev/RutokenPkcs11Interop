using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI40;
using HLA40 = Net.Pkcs11Interop.HighLevelAPI40;

namespace RutokenPkcs11Interop.HighLevelAPI40
{
    public static class Pkcs11Extensions
    {
        public static void FreeBuffer(this HLA40.Pkcs11 pkcs11, IntPtr buffer)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            CKR rv = pkcs11.LowLevelPkcs11.C_EX_FreeBuffer(buffer);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
        }
    }
}
