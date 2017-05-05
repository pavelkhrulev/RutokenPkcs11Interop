using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI41;

namespace RutokenPkcs11Interop.HighLevelAPI41
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

        internal TokenInfoExtended(CK_TOKEN_INFO_EXTENDED ck_token_info_extended)
        {
            _sizeofThisStructure = ck_token_info_extended.SizeofThisStructure;
            TokenType = ck_token_info_extended.TokenType;
            ProtocolNumber = ck_token_info_extended.ProtocolNumber;
            MicrocodeNumber = ck_token_info_extended.MicrocodeNumber;
            OrderNumber = ck_token_info_extended.OrderNumber;
            Flags = ck_token_info_extended.Flags;
            MaxAdminPinLen = ck_token_info_extended.MaxAdminPinLen;
            MinAdminPinLen = ck_token_info_extended.MinAdminPinLen;
            MaxUserPinLen = ck_token_info_extended.MaxUserPinLen;
            MinUserPinLen = ck_token_info_extended.MinUserPinLen;
            MaxAdminRetryCount = ck_token_info_extended.MaxAdminRetryCount;
            AdminRetryCountLeft = ck_token_info_extended.AdminRetryCountLeft;
            MaxUserRetryCount = ck_token_info_extended.MaxUserRetryCount;
            UserRetryCountLeft = ck_token_info_extended.UserRetryCountLeft;
            // Не уверен, что нужно конвертировать
            SerialNumber = ConvertUtils.BytesToUtf8String(ck_token_info_extended.SerialNumber, true);
            TotalMemory = ck_token_info_extended.TotalMemory;
            FreeMemory = ck_token_info_extended.FreeMemory;
            // Не уверен, что нужно конвертировать
            ATR = ConvertUtils.BytesToUtf8String(ck_token_info_extended.ATR, true);
            ATRLen = ck_token_info_extended.ATRLen;
            TokenClass = ck_token_info_extended.TokenClass;
            BatteryVoltage = ck_token_info_extended.BatteryVoltage;
            BodyColor = ck_token_info_extended.BodyColor;
            FirmwareChecksum = ck_token_info_extended.FirmwareChecksum;
        }
    }
}
