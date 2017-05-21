using System;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

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

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_GetJournal(uint slotId, byte[] journal, ref uint journalLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_SetLocalPIN(uint slotId, byte[] userPin, uint userPinLen,
            byte[] newLocalPin, uint localPinLen, uint localPinId);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_GetDriveSize(uint slotId, ref uint driveSize);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_FormatDrive(uint slotId, uint userType,
            byte[] pin, uint pinLen,
            CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams, uint initParamsCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_GetVolumesInfo(uint slotId,
            [Out][MarshalAs(UnmanagedType.LPArray, SizeConst = 1)]CK_VOLUME_INFO_EXTENDED[] info, ref uint infoCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate uint C_EX_ChangeVolumeAttributes(uint slotId, uint userType,
            byte[] pin, uint pinLen,
            uint volumeId, uint newAccessMode, bool permanent);
    }
}
