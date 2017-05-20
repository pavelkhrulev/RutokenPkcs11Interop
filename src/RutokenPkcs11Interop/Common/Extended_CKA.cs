using Net.Pkcs11Interop.Common;

namespace RutokenPkcs11Interop.Common
{
    public enum Extended_CKA : uint
    {
        CKA_GOSTR3410_PARAMS = 0x00000250,
        CKA_GOSTR3411_PARAMS = 0x00000251,
        CKA_GOST28147_PARAMS = 0x00000252,

        CKA_VENDOR_KEY_JOURNAL = (CKA.CKA_VENDOR_DEFINED | 0x2002)
    }
}
