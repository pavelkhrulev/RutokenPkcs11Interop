using System.Runtime.InteropServices;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.LowLevelAPI40
{
    /// <summary>
    /// Структура для представления расширенной информации о токене
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_TOKEN_INFO_EXTENDED
    {
        public uint SizeofThisStructure;

        public RutokenType TokenType;

        public uint ProtocolNumber;

        public uint MicrocodeNumber;

        public uint OrderNumber;

        /// <summary>
        /// Bit flags indicating capabilities and status of the device
        /// </summary>
        public uint Flags;

        public uint MaxAdminPinLen;

        public uint MinAdminPinLen;

        public uint MaxUserPinLen;

        public uint MinUserPinLen;

        public uint MaxAdminRetryCount;

        public uint AdminRetryCountLeft;

        public uint MaxUserRetryCount;

        public uint UserRetryCountLeft;

        /// <summary>
        /// token serial number in Big Endian format
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SerialNumber;

        public uint TotalMemory;

        public uint FreeMemory;

        /// <summary>
        /// atr of the token
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] ATR;

        public uint ATRLen;

        public RutokenClass TokenClass;

        public uint BatteryVoltage;

        public RutokenBodyColor BodyColor;

        public uint FirmwareChecksum;
    }
}
