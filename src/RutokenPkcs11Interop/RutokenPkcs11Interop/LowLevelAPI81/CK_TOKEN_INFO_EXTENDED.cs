using System.Runtime.InteropServices;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.LowLevelAPI81
{
    /// <summary>
    /// Структура для представления расширенной информации о токене
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_TOKEN_INFO_EXTENDED
    {
        public ulong SizeofThisStructure;

        public RutokenType TokenType;

        public ulong ProtocolNumber;

        public ulong MicrocodeNumber;

        public ulong OrderNumber;

        /// <summary>
        /// Bit flags indicating capabilities and status of the device
        /// </summary>
        public ulong Flags;

        public ulong MaxAdminPinLen;

        public ulong MinAdminPinLen;

        public ulong MaxUserPinLen;

        public ulong MinUserPinLen;

        public ulong MaxAdminRetryCount;

        public ulong AdminRetryCountLeft;

        public ulong MaxUserRetryCount;

        public ulong UserRetryCountLeft;

        /// <summary>
        /// token serial number in Big Endian format
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SerialNumber;

        public ulong TotalMemory;

        public ulong FreeMemory;

        /// <summary>
        /// atr of the token
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] ATR;

        public ulong ATRLen;

        public RutokenClass TokenClass;

        public ulong BatteryVoltage;

        public RutokenBodyColor BodyColor;

        public ulong FirmwareChecksum;
    }
}
