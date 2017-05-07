namespace RutokenPkcs11Interop.Common
{
    public enum Extended_CKK : uint
    {
        CKK_GOSTR3410 = 0x00000030,
        CKK_GOSTR3411 = 0x00000031,
        CKK_GOST28147 = 0x00000032,
        CKK_GOSTR3410_512 = Extended_CKM.CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x003
    }
}
