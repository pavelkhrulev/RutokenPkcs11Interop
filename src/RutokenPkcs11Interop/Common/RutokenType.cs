namespace RutokenPkcs11Interop.Common
{
    public enum RutokenType : uint
    {
        Unknown = 0xFF,
        ECP = 0x01,
        LITE = 0x02,
        RUTOKEN = 0x03,
        PINPAD_FAMILY = 0x04,
        ECPDUAL_USB = 0x09,
        ECPDUAL_BT = 0x69,
        ECPDUAL_UART = 0xA9,
        WEB = 0x23,
        SC_JC = 0x41,
        LITE_SC_JC = 0x42,
        ECP_SD = 0x81,
        LITE_SD = 0x82
    }
}
