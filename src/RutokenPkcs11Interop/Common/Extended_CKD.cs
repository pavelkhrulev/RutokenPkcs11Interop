namespace Net.RutokenPkcs11Interop.Common
{
    public enum Extended_CKD : uint
    {
        CKD_CPDIVERSIFY_KDF = 0x00000009,

        CKD_KDF_4357 = (Extended_CKM.CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x025),
        CKD_KDF_GOSTR3411_2012_256 = (Extended_CKM.CK_VENDOR_PKCS11_RU_TEAM_TK26 | 0x026),
    }
}
