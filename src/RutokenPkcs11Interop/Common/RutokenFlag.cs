using System;

namespace Net.RutokenPkcs11Interop.Common
{
    [Flags]
    public enum RutokenFlag : uint
    {
        AdminChangeUserPin = 0x00000001,
        UserChangeUserPin = 0x00000002,
        AdminPinNotDefault = 0x00000004,
        UserPinNotDefault = 0x00000008,
        SupportFKN = 0x00000010,
        SupportSM = 0x00000040,
        HasFlashDrive = 0x00000080,
        CanChangeSMMode = 0x00000100,
        FWChecksumUnavailable = 0x40000000,
        FWChecksumInvalid = 0x80000000
    }
}
