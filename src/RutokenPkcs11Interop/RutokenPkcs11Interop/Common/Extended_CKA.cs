using Net.Pkcs11Interop.Common;

namespace RutokenPkcs11Interop.Common
{
    public enum Extended_CKA : uint
    {
        CKA_GOSTR3410_PARAMS = 0x00000250,
        CKA_GOSTR3411_PARAMS = 0x00000251,
        CKA_GOST28147_PARAMS = 0x00000252,

        /* Ключ только для операций с журналом - тип CK_BBOOL */
        CKA_VENDOR_KEY_JOURNAL = (CKA.CKA_VENDOR_DEFINED | 0x2002),
        /* Операция подписи требует ввода PIN - тип CK_BBOOL */
        CKA_VENDOR_KEY_PIN_ENTER = (CKA.CKA_VENDOR_DEFINED | 0x2000),
        /* Операция подписи требует подтверждения - тип CK_BBOOL */
        CKA_VENDOR_KEY_CONFIRM_OP = (CKA.CKA_VENDOR_DEFINED | 0x2001)
    }
}
