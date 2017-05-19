using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.HighLevelAPI41;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public static class SlotExtensions
    {
        public static TokenInfoExtended GetTokenInfoExtended(this Slot slot)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    HighLevelAPI41.TokenInfoExtended tokenInfoExtended = slot.HLA41Slot.GetTokenInfoExtended();
                    return new HighLevelAPI.TokenInfoExtended(tokenInfoExtended);
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

        public static void InitTokenExtended(this Slot slot, string pin, RutokenInitParam initParam)
        {
            if (pin == null)
                throw new ArgumentNullException("pin");

            if (initParam == null)
                throw new ArgumentNullException("initParam");

            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    slot.HLA41Slot.InitTokenExtended(pin, initParam.RutokenInitParam41);
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
}
