using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class TokenInfoExtended
    {
        private HighLevelAPI41.TokenInfoExtended _tokenInfoExtended41 = null;

        public RutokenType TokenType
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint ProtocolNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint MicrocodeNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint OrderNumber
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint Flags
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint MaxAdminPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint MinAdminPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint MaxUserPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint MinUserPinLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint MaxAdminRetryCount
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint AdminRetryCountLeft
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint MaxUserRetryCount
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint UserRetryCountLeft
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint TotalMemory
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint FreeMemory
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint ATRLen
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint BatteryVoltage
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint FirmwareChecksum
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        throw new NotImplementedException();
                    }
                }
            }
        }

        internal TokenInfoExtended(HighLevelAPI41.TokenInfoExtended tokenInfoExtended)
        {
            if (tokenInfoExtended == null)
                throw new ArgumentNullException("tokenInfoExtended");

            _tokenInfoExtended41 = tokenInfoExtended;
        }
    }
}
