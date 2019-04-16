using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class TokenInfoExtended
    {
        private readonly HighLevelAPI40.TokenInfoExtended _tokenInfoExtended40 = null;

        private readonly HighLevelAPI41.TokenInfoExtended _tokenInfoExtended41 = null;

        private readonly HighLevelAPI80.TokenInfoExtended _tokenInfoExtended80 = null;

        private readonly HighLevelAPI81.TokenInfoExtended _tokenInfoExtended81 = null;

        public RutokenType TokenType
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.TokenType;
                    }
                    else
                    {
                        return _tokenInfoExtended41.TokenType;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.TokenType;
                    }
                    else
                    {
                        return _tokenInfoExtended81.TokenType;
                    }
                }
            }
        }

        public ulong ProtocolNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.ProtocolNumber;
                    }
                    else
                    {
                        return _tokenInfoExtended41.ProtocolNumber;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.ProtocolNumber;
                    }
                    else
                    {
                        return _tokenInfoExtended81.ProtocolNumber;
                    }
                }
            }
        }

        public ulong MicrocodeNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.MicrocodeNumber;
                    }
                    else
                    {
                        return _tokenInfoExtended41.MicrocodeNumber;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.MicrocodeNumber;
                    }
                    else
                    {
                        return _tokenInfoExtended81.MicrocodeNumber;
                    }
                }
            }
        }

        public ulong OrderNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.OrderNumber;
                    }
                    else
                    {
                        return _tokenInfoExtended41.OrderNumber;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.OrderNumber;
                    }
                    else
                    {
                        return _tokenInfoExtended81.OrderNumber;
                    }
                }
            }
        }

        public ulong Flags
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.Flags;
                    }
                    else
                    {
                        return _tokenInfoExtended41.Flags;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.Flags;
                    }
                    else
                    {
                        return _tokenInfoExtended81.Flags;
                    }
                }
            }
        }

        public ulong MaxAdminPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.MaxAdminPinLen;
                    }
                    else
                    {
                        return _tokenInfoExtended41.MaxAdminPinLen;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.MaxAdminPinLen;
                    }
                    else
                    {
                        return _tokenInfoExtended81.MaxAdminPinLen;
                    }
                }
            }
        }

        public ulong MinAdminPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.MinAdminPinLen;
                    }
                    else
                    {
                        return _tokenInfoExtended41.MinAdminPinLen;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.MinAdminPinLen;
                    }
                    else
                    {
                        return _tokenInfoExtended81.MinAdminPinLen;
                    }
                }
            }
        }

        public ulong MaxUserPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.MaxUserPinLen;
                    }
                    else
                    {
                        return _tokenInfoExtended41.MaxUserPinLen;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.MaxUserPinLen;
                    }
                    else
                    {
                        return _tokenInfoExtended81.MaxUserPinLen;
                    }
                }
            }
        }

        public ulong MinUserPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.MinUserPinLen;
                    }
                    else
                    {
                        return _tokenInfoExtended41.MinUserPinLen;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.MinUserPinLen;
                    }
                    else
                    {
                        return _tokenInfoExtended81.MinUserPinLen;
                    }
                }
            }
        }

        public ulong MaxAdminRetryCount
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.MaxAdminRetryCount;
                    }
                    else
                    {
                        return _tokenInfoExtended41.MaxAdminRetryCount;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.MaxAdminRetryCount;
                    }
                    else
                    {
                        return _tokenInfoExtended81.MaxAdminRetryCount;
                    }
                }
            }
        }

        public ulong AdminRetryCountLeft
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.AdminRetryCountLeft;
                    }
                    else
                    {
                        return _tokenInfoExtended41.AdminRetryCountLeft;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.AdminRetryCountLeft;
                    }
                    else
                    {
                        return _tokenInfoExtended81.AdminRetryCountLeft;
                    }
                }
            }
        }

        public ulong MaxUserRetryCount
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.MaxUserRetryCount;
                    }
                    else
                    {
                        return _tokenInfoExtended41.MaxUserRetryCount;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.MaxUserRetryCount;
                    }
                    else
                    {
                        return _tokenInfoExtended81.MaxUserRetryCount;
                    }
                }
            }
        }

        public ulong UserRetryCountLeft
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.UserRetryCountLeft;
                    }
                    else
                    {
                        return _tokenInfoExtended41.UserRetryCountLeft;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.UserRetryCountLeft;
                    }
                    else
                    {
                        return _tokenInfoExtended81.UserRetryCountLeft;
                    }
                }
            }
        }

        public string SerialNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.SerialNumber;
                    }
                    else
                    {
                        return _tokenInfoExtended41.SerialNumber;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.SerialNumber;
                    }
                    else
                    {
                        return _tokenInfoExtended81.SerialNumber;
                    }
                }
            }
        }

        public ulong TotalMemory
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.TotalMemory;
                    }
                    else
                    {
                        return _tokenInfoExtended41.TotalMemory;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.TotalMemory;
                    }
                    else
                    {
                        return _tokenInfoExtended81.TotalMemory;
                    }
                }
            }
        }

        public ulong FreeMemory
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.FreeMemory;
                    }
                    else
                    {
                        return _tokenInfoExtended41.FreeMemory;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.FreeMemory;
                    }
                    else
                    {
                        return _tokenInfoExtended81.FreeMemory;
                    }
                }
            }
        }

        public string ATR
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.ATR;
                    }
                    else
                    {
                        return _tokenInfoExtended41.ATR;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.ATR;
                    }
                    else
                    {
                        return _tokenInfoExtended81.ATR;
                    }
                }
            }
        }

        public ulong ATRLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.ATRLen;
                    }
                    else
                    {
                        return _tokenInfoExtended41.ATRLen;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.ATRLen;
                    }
                    else
                    {
                        return _tokenInfoExtended81.ATRLen;
                    }
                }
            }
        }

        public RutokenClass TokenClass
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.TokenClass;
                    }
                    else
                    {
                        return _tokenInfoExtended41.TokenClass;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.TokenClass;
                    }
                    else
                    {
                        return _tokenInfoExtended81.TokenClass;
                    }
                }
            }
        }

        public ulong BatteryVoltage
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.BatteryVoltage;
                    }
                    else
                    {
                        return _tokenInfoExtended41.BatteryVoltage;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.BatteryVoltage;
                    }
                    else
                    {
                        return _tokenInfoExtended81.BatteryVoltage;
                    }
                }
            }
        }

        public RutokenBodyColor BodyColor
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.BodyColor;
                    }
                    else
                    {
                        return _tokenInfoExtended41.BodyColor;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.BodyColor;
                    }
                    else
                    {
                        return _tokenInfoExtended81.BodyColor;
                    }
                }
            }
        }

        public ulong FirmwareChecksum
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended40.FirmwareChecksum;
                    }
                    else
                    {
                        return _tokenInfoExtended41.FirmwareChecksum;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _tokenInfoExtended80.FirmwareChecksum;
                    }
                    else
                    {
                        return _tokenInfoExtended81.FirmwareChecksum;
                    }
                }
            }
        }

        internal TokenInfoExtended(HighLevelAPI40.TokenInfoExtended tokenInfoExtended)
        {
            if (tokenInfoExtended == null)
                throw new ArgumentNullException(nameof(tokenInfoExtended));

            _tokenInfoExtended40 = tokenInfoExtended;
        }

        internal TokenInfoExtended(HighLevelAPI41.TokenInfoExtended tokenInfoExtended)
        {
            if (tokenInfoExtended == null)
                throw new ArgumentNullException(nameof(tokenInfoExtended));

            _tokenInfoExtended41 = tokenInfoExtended;
        }

        internal TokenInfoExtended(HighLevelAPI80.TokenInfoExtended tokenInfoExtended)
        {
            if (tokenInfoExtended == null)
                throw new ArgumentNullException(nameof(tokenInfoExtended));

            _tokenInfoExtended80 = tokenInfoExtended;
        }

        internal TokenInfoExtended(HighLevelAPI81.TokenInfoExtended tokenInfoExtended)
        {
            if (tokenInfoExtended == null)
                throw new ArgumentNullException(nameof(tokenInfoExtended));

            _tokenInfoExtended81 = tokenInfoExtended;
        }
    }
}
