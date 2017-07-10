using System;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.LowLevelAPI81;

namespace RutokenPkcs11Interop.LowLevelAPI81
{
    internal static class RutokenNativeMethods
    {
        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_GetTokenInfoExtended(ulong slotId, ref CK_TOKEN_INFO_EXTENDED info);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_InitToken(ulong slotId, byte[] pin, ulong pinLen, ref CK_RUTOKEN_INIT_PARAM initInfo);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_UnblockUserPIN(ulong session);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_SetTokenName(ulong session, byte[] label, ulong labelLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_GetTokenName(ulong session, byte[] label, ref ulong labelLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_GetJournal(ulong slotId, byte[] journal, ref ulong journalLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_SignInvisibleInit(ulong session, ref CK_MECHANISM mechanism, ulong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_SignInvisible(
            ulong session, byte[] data, ulong dataLen, byte[] signature, ref ulong signatureLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_SetLocalPIN(ulong slotId, byte[] userPin, ulong userPinLen,
            byte[] newLocalPin, ulong localPinLen, ulong localPinId);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_GetDriveSize(ulong slotId, ref ulong driveSize);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_FormatDrive(ulong slotId, ulong userType,
            byte[] pin, ulong pinLen,
            CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams, ulong initParamsCount);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_GetVolumesInfo(ulong slotId,
            [Out][MarshalAs(UnmanagedType.LPArray, SizeConst = 1)]CK_VOLUME_INFO_EXTENDED[] info, ref ulong infoCount);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_ChangeVolumeAttributes(ulong slotId, ulong userType,
            byte[] pin, ulong pinLen,
            ulong volumeId, ulong newAccessMode, bool permanent);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_SetLicense(
            ulong session, ulong licenseNum, byte[] license, ulong licenseLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_GetLicense(
            ulong session, ulong licenseNum, byte[] license, ref ulong licenseLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_GenerateActivationPassword(ulong session, ulong passwordNumber,
            byte[] password, ref ulong passwordSize, ulong passwordCharacterSet);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_LoadActivationKey(ulong session, byte[] key, ulong keySize);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_SetActivationPassword(ulong slotId, byte[] password);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_TokenManage(ulong session, ulong mode, IntPtr value);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_SlotManage(ulong slotId, ulong mode, IntPtr value);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_WrapKey(ulong session, ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, ulong keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            ulong baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref ulong wrappedKeyLen, ref ulong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_UnwrapKey(ulong session, ref CK_MECHANISM derivationMechanism,
            ulong baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, ulong wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, ulong keyAttributeCount,
            ref ulong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_CreateCSR(ulong session, ulong publicKey,
            IntPtr[] dn, ulong dnLength,
            out IntPtr csr, out ulong csrLength,
            ulong privateKey,
            IntPtr[] attributes, ulong attributesLength,
            IntPtr[] extensions, ulong extensionsLength);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_GetCertificateInfoText(
            ulong session, ulong cert, out IntPtr info, out ulong infoLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_PKCS7Sign(
            ulong session, byte[] data, ulong dataLen,
            ulong cert,
            out IntPtr envelope, out ulong encelopeLen,
            ulong privateKey,
            ulong[] certificates, ulong certificatesLen, ulong flags);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong C_EX_FreeBuffer(IntPtr buffer);
    }
}
