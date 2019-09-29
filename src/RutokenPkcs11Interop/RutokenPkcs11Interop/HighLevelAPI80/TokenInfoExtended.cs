using System;
using System.Linq;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI80;

namespace RutokenPkcs11Interop.HighLevelAPI80
{
    public class TokenInfoExtended
    {
        private ulong _sizeofThisStructure;

        public RutokenType TokenType { get; } = RutokenType.Unknown;

        public ulong ProtocolNumber { get; } = 0;

        public ulong MicrocodeNumber { get; } = 0;

        public ulong OrderNumber { get; } = 0;

        public ulong Flags { get; } = 0;

        public ulong MaxAdminPinLen { get; } = 0;

        public ulong MinAdminPinLen { get; } = 0;

        public ulong MaxUserPinLen { get; } = 0;

        public ulong MinUserPinLen { get; } = 0;

        public ulong MaxAdminRetryCount { get; } = 0;

        public ulong AdminRetryCountLeft { get; } = 0;

        public ulong MaxUserRetryCount { get; } = 0;

        public ulong UserRetryCountLeft { get; } = 0;

        public string SerialNumber { get; } = null;

        public ulong TotalMemory { get; } = 0;

        public ulong FreeMemory { get; } = 0;

        public string ATR { get; } = null;

        public ulong ATRLen { get; } = 0;

        public RutokenClass TokenClass { get; } = RutokenClass.Unknown;

        public ulong BatteryVoltage { get; } = 0;

        public RutokenBodyColor BodyColor { get; } = RutokenBodyColor.Unknown;

        public ulong FirmwareChecksum { get; } = 0;

        internal TokenInfoExtended(CK_TOKEN_INFO_EXTENDED ckTokenInfoExtended)
        {
            _sizeofThisStructure = ckTokenInfoExtended.SizeofThisStructure;
            TokenType = (RutokenType) ckTokenInfoExtended.TokenType;
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
            TokenClass = (RutokenClass) ckTokenInfoExtended.TokenClass;
            BatteryVoltage = ckTokenInfoExtended.BatteryVoltage;
            BodyColor = (RutokenBodyColor) ckTokenInfoExtended.BodyColor;
            FirmwareChecksum = ckTokenInfoExtended.FirmwareChecksum;
        }
    }
}
