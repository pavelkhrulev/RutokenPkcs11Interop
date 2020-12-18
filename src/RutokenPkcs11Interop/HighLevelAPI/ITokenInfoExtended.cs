using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public interface ITokenInfoExtended
    {
        RutokenType TokenType { get; }

        ulong ProtocolNumber { get; }

        ulong MicrocodeNumber { get; }

        ulong OrderNumber { get; }

        ulong Flags { get; }

        ulong MaxAdminPinLen { get; }

        ulong MinAdminPinLen { get; }

        ulong MaxUserPinLen { get; }

        ulong MinUserPinLen { get; }

        ulong MaxAdminRetryCount { get; }

        ulong AdminRetryCountLeft { get; }

        ulong MaxUserRetryCount { get; }

        ulong UserRetryCountLeft { get; }

        string SerialNumber { get; }

        ulong TotalMemory { get; }

        ulong FreeMemory { get; }

        string ATR { get; }

        ulong ATRLen { get; }

        RutokenClass TokenClass { get; }

        ulong BatteryVoltage { get; }

        RutokenBodyColor BodyColor { get; }

        ulong FirmwareChecksum { get; }

    }
}
