using System;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.LowLevelAPI80;

using NativeULong = System.UInt64;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI80
{
    internal static class RutokenNativeMethods
    {
        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_GetTokenInfoExtended(NativeULong slotId, ref CK_TOKEN_INFO_EXTENDED info);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_InitToken(NativeULong slotId, byte[] pin, NativeULong pinLen, ref CK_RUTOKEN_INIT_PARAM initInfo);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_UnblockUserPIN(NativeULong session);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_SetTokenName(NativeULong session, byte[] label, NativeULong labelLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_GetTokenName(NativeULong session, byte[] label, ref NativeULong labelLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_GetJournal(NativeULong slotId, byte[] journal, ref NativeULong journalLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_SignInvisibleInit(NativeULong session, ref CK_MECHANISM mechanism, NativeULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_SignInvisible(
            NativeULong session, byte[] data, NativeULong dataLen, byte[] signature, ref NativeULong signatureLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_SetLocalPIN(NativeULong slotId, byte[] userPin, NativeULong userPinLen,
            byte[] newLocalPin, NativeULong localPinLen, NativeULong localPinId);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_GetDriveSize(NativeULong slotId, ref NativeULong driveSize);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_FormatDrive(NativeULong slotId, NativeULong userType,
            byte[] pin, NativeULong pinLen,
            CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams, NativeULong initParamsCount);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_GetVolumesInfo(NativeULong slotId,
            [Out][MarshalAs(UnmanagedType.LPArray, SizeConst = 1)]CK_VOLUME_INFO_EXTENDED[] info, ref NativeULong infoCount);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_ChangeVolumeAttributes(NativeULong slotId, NativeULong userType,
            byte[] pin, NativeULong pinLen,
            NativeULong volumeId, NativeULong newAccessMode, bool permanent);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_SetLicense(
            NativeULong session, NativeULong licenseNum, byte[] license, NativeULong licenseLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_GetLicense(
            NativeULong session, NativeULong licenseNum, byte[] license, ref NativeULong licenseLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_GenerateActivationPassword(NativeULong session, NativeULong passwordNumber,
            byte[] password, ref NativeULong passwordSize, NativeULong passwordCharacterSet);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_LoadActivationKey(NativeULong session, byte[] key, NativeULong keySize);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_SetActivationPassword(NativeULong slotId, byte[] password);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_TokenManage(NativeULong session, NativeULong mode, IntPtr value);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_SlotManage(NativeULong slotId, NativeULong mode, IntPtr value);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_WrapKey(NativeULong session, ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, NativeULong keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            NativeULong baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref NativeULong wrappedKeyLen, ref NativeULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_UnwrapKey(NativeULong session, ref CK_MECHANISM derivationMechanism,
            NativeULong baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, NativeULong wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, NativeULong keyAttributeCount,
            ref NativeULong key);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_CreateCSR(NativeULong session, NativeULong publicKey,
            IntPtr[] dn, NativeULong dnLength,
            out IntPtr csr, out NativeULong csrLength,
            NativeULong privateKey,
            IntPtr[] attributes, NativeULong attributesLength,
            IntPtr[] extensions, NativeULong extensionsLength);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_GetCertificateInfoText(
            NativeULong session, NativeULong cert, out IntPtr info, out NativeULong infoLen);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_PKCS7Sign(
            NativeULong session, byte[] data, NativeULong dataLen,
            NativeULong cert,
            out IntPtr envelope, out NativeULong encelopeLen,
            NativeULong privateKey,
            NativeULong[] certificates, NativeULong certificatesLen, NativeULong flags);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_PKCS7VerifyInit(
            NativeULong session, byte[] cms, NativeULong cmsSize,
            ref CK_VENDOR_X509_STORE store, NativeULong mode,
            NativeULong flags);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_PKCS7Verify(
            NativeULong session,
            out IntPtr data, out NativeULong dataSize,
            out IntPtr signerCertificates, out NativeULong signerCertificatesCount);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_PKCS7VerifyUpdate(
            NativeULong session, byte[] data, NativeULong dataSize);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_PKCS7VerifyFinal(
            NativeULong session,
            out IntPtr signerCertificates, out NativeULong signerCertificatesCount);

        [DllImport("__Internal", CallingConvention = CallingConvention.Cdecl)]
        internal static extern NativeULong C_EX_FreeBuffer(IntPtr buffer);
    }
}
