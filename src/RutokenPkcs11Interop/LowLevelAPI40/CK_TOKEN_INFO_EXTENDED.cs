using System.Runtime.InteropServices;

using NativeULong = System.UInt32;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI40
{
    /// <summary>
    /// Структура для представления расширенной информации о токене
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_TOKEN_INFO_EXTENDED
    {
        public NativeULong SizeofThisStructure;

        public NativeULong TokenType;

        public NativeULong ProtocolNumber;

        public NativeULong MicrocodeNumber;

        public NativeULong OrderNumber;

        /// <summary>
        /// Bit flags indicating capabilities and status of the device
        /// </summary>
        public NativeULong Flags;

        public NativeULong MaxAdminPinLen;

        public NativeULong MinAdminPinLen;

        public NativeULong MaxUserPinLen;

        public NativeULong MinUserPinLen;

        public NativeULong MaxAdminRetryCount;

        public NativeULong AdminRetryCountLeft;

        public NativeULong MaxUserRetryCount;

        public NativeULong UserRetryCountLeft;

        /// <summary>
        /// token serial number in Big Endian format
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SerialNumber;

        public NativeULong TotalMemory;

        public NativeULong FreeMemory;

        /// <summary>
        /// atr of the token
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] ATR;

        public NativeULong ATRLen;

        public NativeULong TokenClass;

        public NativeULong BatteryVoltage;

        public NativeULong BodyColor;

        public NativeULong FirmwareChecksum;
    }
}
