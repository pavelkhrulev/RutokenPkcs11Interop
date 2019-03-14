using System;
using System.Linq;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI40;

namespace RutokenPkcs11Interop.HighLevelAPI40
{
    public class TokenInfoExtended
    {
        private uint _sizeofThisStructure;

        public RutokenType TokenType { get; } = RutokenType.Unknown;

        public uint ProtocolNumber { get; } = 0;

        public uint MicrocodeNumber { get; } = 0;

        public uint OrderNumber { get; } = 0;

        public uint Flags { get; } = 0;

        public uint MaxAdminPinLen { get; } = 0;

        public uint MinAdminPinLen { get; } = 0;

        public uint MaxUserPinLen { get; } = 0;

        public uint MinUserPinLen { get; } = 0;

        public uint MaxAdminRetryCount { get; } = 0;

        public uint AdminRetryCountLeft { get; } = 0;

        public uint MaxUserRetryCount { get; } = 0;

        public uint UserRetryCountLeft { get; } = 0;

        public string SerialNumber { get; } = null;

        public uint TotalMemory { get; } = 0;

        public uint FreeMemory { get; } = 0;

        public string ATR { get; } = null;

        public uint ATRLen { get; } = 0;

        public RutokenClass TokenClass { get; } = RutokenClass.Unknown;

        public uint BatteryVoltage { get; } = 0;

        public RutokenBodyColor BodyColor { get; } = RutokenBodyColor.Unknown;

        public uint FirmwareChecksum { get; } = 0;

        internal TokenInfoExtended(CK_TOKEN_INFO_EXTENDED ckTokenInfoExtended)
        {
            _sizeofThisStructure = ckTokenInfoExtended.SizeofThisStructure;
            TokenType = ckTokenInfoExtended.TokenType;
            ProtocolNumber = ckTokenInfoExtended.ProtocolNumber;
            MicrocodeNumber = ckTokenInfoExtended.MicrocodeNumber;
            OrderNumber = ckTokenInfoExtended.OrderNumber;
            Flags = ckTokenInfoExtended.Flags;
            MaxAdminPinLen = ckTokenInfoExtended.MaxAdminPinLen;
            MinAdminPinLen = ckTokenInfoExtended.MinAdminPinLen;
            MaxUserPinLen = ckTokenInfoExtended.MaxUserPinLen;
            MinUserPinLen = ckTokenInfoExtended.MinUserPinLen;
            MaxAdminRetryCount = ckTokenInfoExtended.MaxAdminRetryCount;
            AdminRetryCountLeft = ckTokenInfoExtended.AdminRetryCountLeft;
            MaxUserRetryCount = ckTokenInfoExtended.MaxUserRetryCount;
            UserRetryCountLeft = ckTokenInfoExtended.UserRetryCountLeft;
            // TODO: может стоит оставить байты
            SerialNumber = ConvertUtils.BytesToHexString(ckTokenInfoExtended.SerialNumber);
            TotalMemory = ckTokenInfoExtended.TotalMemory;
            FreeMemory = ckTokenInfoExtended.FreeMemory;
            // TODO: может стоит оставить байты
            ATR = ConvertUtils.BytesToHexString(ckTokenInfoExtended.ATR
                .Take(Convert.ToInt32(ckTokenInfoExtended.ATRLen))
                .ToArray());
            ATRLen = ckTokenInfoExtended.ATRLen;
            TokenClass = ckTokenInfoExtended.TokenClass;
            BatteryVoltage = ckTokenInfoExtended.BatteryVoltage;
            BodyColor = ckTokenInfoExtended.BodyColor;
            FirmwareChecksum = ckTokenInfoExtended.FirmwareChecksum;
        }
    }
}
