using System;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI41;
using HLA41 = Net.Pkcs11Interop.HighLevelAPI41;

namespace RutokenPkcs11Interop.HighLevelAPI41
{
    public static class SlotExtensions
    {
        public static TokenInfoExtended GetTokenInfoExtended(this HLA41.Slot slot)
        {
            var tokenInfo = new CK_TOKEN_INFO_EXTENDED
            {
                SizeofThisStructure = Convert.ToUInt32(Marshal.SizeOf(typeof(CK_TOKEN_INFO_EXTENDED)))
            };

            CKR rv = slot.LowLevelPkcs11.C_EX_GetTokenInfoExtended(slot.SlotId, ref tokenInfo);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetTokenInfoExtended", rv);

            return new TokenInfoExtended(tokenInfo);
        }

        public static void InitTokenExtended(this HLA41.Slot slot, byte[] pin, uint pinLen, RutokenInitParam initParam)
        {
            if (pin == null)
                throw new ArgumentNullException("pin");

            if (initParam == null)
                throw new ArgumentNullException("initParam");

            //CK_RUTOKEN_INIT_PARAM ckInitParam = initParam
            //CKR rv = slot.LowLevelPkcs11.C_EX_InitToken(slot.SlotId, pin, pinLen, ref initParam);
            //if (rv != CKR.CKR_OK)
            //    throw new Pkcs11Exception("C_EX_InitToken", rv);
        }
    }
}
