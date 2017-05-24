using System;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.LowLevelAPI41;

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
        internal static extern uint C_EX_SignInvisibleInit(uint session, ref CK_MECHANISM mechanism, uint key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_SignInvisible(
            uint session, byte[] data, uint dataLen, byte[] signature, ref uint signatureLen);

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

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_SetLicense(
            uint session, uint licenseNum, byte[] license, uint licenseLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_GetLicense(
            uint session, uint licenseNum, byte[] license, ref uint licenseLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_GenerateActivationPassword(uint session, uint passwordNumber,
            byte[] password, ref uint passwordSize, uint passwordCharacterSet);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_LoadActivationKey(uint session, byte[] key, uint keySize);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_SetActivationPassword(uint slotId, byte[] password);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_TokenManage(uint session, uint mode, IntPtr value);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_SlotManage(uint slotId, uint mode, IntPtr value);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_WrapKey(uint session, ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, uint keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            uint baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref uint wrappedKeyLen, ref uint key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_UnwrapKey(uint session, ref CK_MECHANISM derivationMechanism,
            uint baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, uint wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, uint keyAttributeCount,
            ref uint key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_CreateCSR(uint session, uint publicKey,
            IntPtr dn, uint dnLength,
            out IntPtr csr, out uint csrLength,
            uint privateKey,
            IntPtr attributes, uint attributesLength,
            IntPtr extensions, uint extensionsLength);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_GetCertificateInfoText(
            uint session, uint cert, out IntPtr info, out uint infoLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_PKCS7Sign(
            uint session, byte[] data, uint dataLen,
            uint cert,
            out IntPtr envelope, out uint encelopeLen,
            uint privateKey,
            uint[] certificates, uint certificatesLen, uint flags);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint C_EX_FreeBuffer(IntPtr buffer);
    }
}
