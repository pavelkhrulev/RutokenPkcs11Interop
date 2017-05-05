using System;
using System.Runtime.InteropServices;
using System.Text;

namespace RutokenPkcs11Interop.LowLevelAPI41
{
    internal static class RutokenDelegates
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_GetTokenInfoExtendedDelegate(uint slotId, ref CK_TOKEN_INFO_EXTENDED info);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_InitToken(uint slotId, byte[] pin, uint pinLen, ref CK_RUTOKEN_INIT_PARAM initInfo);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_UnblockUserPIN(uint session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_SetTokenName(uint session, byte[] label, uint labelLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_GetTokenName(uint session, byte[] label, ref uint labelLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal delegate uint C_EX_CreateCSR(uint session, uint publicKey,
            IntPtr dn, uint dnLength,
            out IntPtr csr, out uint csrLength,
            uint privateKey,
            IntPtr attributes, uint attributesLength,
            IntPtr extensions, uint extensionsLength);
    }
}
