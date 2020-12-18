namespace Net.RutokenPkcs11Interop.Common
{
    public enum RutokenClass : uint
    {
        Unknown = 0xFFFFFFFF,
        S = 0x00,
        ECP = 0x01,
        LITE = 0x02,
        WEB = 0x03,
        PINPAD = 0x04,
        ECPDUAL = 0x09
    }
}
