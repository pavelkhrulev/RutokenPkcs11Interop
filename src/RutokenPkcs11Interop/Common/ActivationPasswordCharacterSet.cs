namespace Net.RutokenPkcs11Interop.Common
{
    public enum ActivationPasswordCharacterSet : uint
    {
        // Заглавные буквы латинского алфавита без O и цифры без 0
        CapsAndDigits = 0x00,
        // Заглавные буквы латинского алфавита
        CapsOnly = 0x01
    }
}
