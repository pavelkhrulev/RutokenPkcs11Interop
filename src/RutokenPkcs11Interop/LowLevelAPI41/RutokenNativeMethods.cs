using System.Runtime.InteropServices;

namespace RutokenPkcs11Interop.LowLevelAPI41
{
    internal static class RutokenNativeMethods
    {
        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_GetTokenInfoExtended(uint slotId, ref CK_TOKEN_INFO_EXTENDED info);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_InitToken(uint slotId, byte[] pin, uint pinLen, ref CK_RUTOKEN_INIT_PARAM initInfo);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_UnblockUserPIN(uint session);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_SetTokenName(uint session, byte[] label, uint labelLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_GetTokenName(uint session, byte[] label, ref uint labelLen);
    }
}
