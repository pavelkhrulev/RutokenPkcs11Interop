using System;
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

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_GetJournal(uint slotId, byte[] journal, ref uint journalLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_SetLocalPIN(uint slotId, byte[] userPin, uint userPinLen,
            byte[] newLocalPin, uint localPinLen, uint localPinId);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_GetDriveSize(uint slotId, ref uint driveSize);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_FormatDrive(uint slotId, uint userType,
            byte[] pin, uint pinLen,
            CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams, uint initParamsCount);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_GetVolumesInfo(uint slotId,
            [Out][MarshalAs(UnmanagedType.LPArray, SizeConst = 1)]CK_VOLUME_INFO_EXTENDED[] info, ref uint infoCount);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_ChangeVolumeAttributes(uint slotId, uint userType,
            byte[] pin, uint pinLen,
            uint volumeId, uint newAccessMode, bool permanent);
    }
}
