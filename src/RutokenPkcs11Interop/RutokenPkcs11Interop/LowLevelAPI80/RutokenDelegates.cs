using System;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.LowLevelAPI80;
using Net.Pkcs11Interop.Common;
using NativeULong = System.UInt32;

// Note: Code in this file is generated automatically.

namespace RutokenPkcs11Interop.LowLevelAPI80
{
    internal class RutokenDelegates
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_GetTokenInfoExtendedDelegate(ulong slotId, ref CK_TOKEN_INFO_EXTENDED info);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_InitTokenDelegate(ulong slotId, byte[] pin, ulong pinLen, ref CK_RUTOKEN_INIT_PARAM initInfo);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_UnblockUserPINDelegate(ulong session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_SetTokenNameDelegate(ulong session, byte[] label, ulong labelLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_GetTokenNameDelegate(ulong session, byte[] label, ref ulong labelLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_GetJournalDelegate(ulong slotId, byte[] journal, ref ulong journalLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_SignInvisibleInitDelegate(ulong session, ref CK_MECHANISM mechanism, ulong key);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_SignInvisibleDelegate(
            ulong session, byte[] data, ulong dataLen, byte[] signature, ref ulong signatureLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_SetLocalPINDelegate(ulong slotId, byte[] userPin, ulong userPinLen,
            byte[] newLocalPin, ulong localPinLen, ulong localPinId);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_GetDriveSizeDelegate(ulong slotId, ref ulong driveSize);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_FormatDriveDelegate(ulong slotId, ulong userType,
            byte[] pin, ulong pinLen,
            CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams, ulong initParamsCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_GetVolumesInfoDelegate(ulong slotId,
            [Out][MarshalAs(UnmanagedType.LPArray, SizeConst = 1)] CK_VOLUME_INFO_EXTENDED[] info, ref ulong infoCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_ChangeVolumeAttributesDelegate(ulong slotId, ulong userType,
            byte[] pin, ulong pinLen,
            ulong volumeId, ulong newAccessMode, bool permanent);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_SetLicenseDelegate(
            ulong session, ulong licenseNum, byte[] license, ulong licenseLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_GetLicenseDelegate(
            ulong session, ulong licenseNum, byte[] license, ref ulong licenseLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_GenerateActivationPasswordDelegate(ulong session, ulong passwordNumber,
            byte[] password, ref ulong passwordSize, ulong passwordCharacterSet);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_LoadActivationKeyDelegate(ulong session, byte[] key, ulong keySize);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_SetActivationPasswordDelegate(ulong slotId, byte[] password);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_TokenManageDelegate(ulong session, ulong mode, IntPtr value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_SlotManageDelegate(ulong slotId, ulong mode, IntPtr value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_WrapKeyDelegate(ulong session, ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, ulong keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            ulong baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref ulong wrappedKeyLen, ref ulong key);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_UnwrapKeyDelegate(ulong session, ref CK_MECHANISM derivationMechanism,
            ulong baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, ulong wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, ulong keyAttributeCount,
            ref ulong key);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_CreateCSRDelegate(ulong session, ulong publicKey,
            IntPtr[] dn, ulong dnLength,
            out IntPtr csr, out ulong csrLength,
            ulong privateKey,
            IntPtr[] attributes, ulong attributesLength,
            IntPtr[] extensions, ulong extensionsLength);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_GetCertificateInfoTextDelegate(
            ulong session, ulong cert, out IntPtr info, out ulong infoLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_PKCS7SignDelegate(
            ulong session, byte[] data, ulong dataLen,
            ulong cert,
            out IntPtr envelope, out ulong encelopeLen,
            ulong privateKey,
            ulong[] certificates, ulong certificatesLen, ulong flags);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_PKCS7VerifyInitDelegate(
            ulong session, byte[] cms, ulong cmsSize,
            ref CK_VENDOR_X509_STORE store, ulong mode,
            ulong flags);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_PKCS7VerifyDelegate(
            ulong session,
            out IntPtr data, out ulong dataSize,
            out IntPtr signerCertificates, out ulong signerCertificatesCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_PKCS7VerifyUpdateDelegate(
            ulong session, byte[] data, ulong dataSize);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_PKCS7VerifyFinalDelegate(
            ulong session,
            out IntPtr signerCertificates, out ulong signerCertificatesCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate ulong C_EX_FreeBufferDelegate(IntPtr buffer);

        internal C_EX_GetTokenInfoExtendedDelegate C_EX_GetTokenInfoExtended = null;
        internal C_EX_InitTokenDelegate C_EX_InitToken = null;
        internal C_EX_UnblockUserPINDelegate C_EX_UnblockUserPIN = null;
        internal C_EX_SetTokenNameDelegate C_EX_SetTokenName = null;
        internal C_EX_GetTokenNameDelegate C_EX_GetTokenName = null;
        internal C_EX_GetJournalDelegate C_EX_GetJournal = null;
        internal C_EX_SignInvisibleInitDelegate C_EX_SignInvisibleInit = null;
        internal C_EX_SignInvisibleDelegate C_EX_SignInvisible = null;
        internal C_EX_SetLocalPINDelegate C_EX_SetLocalPIN = null;
        internal C_EX_GetDriveSizeDelegate C_EX_GetDriveSize = null;
        internal C_EX_FormatDriveDelegate C_EX_FormatDrive = null;
        internal C_EX_GetVolumesInfoDelegate C_EX_GetVolumesInfo = null;
        internal C_EX_ChangeVolumeAttributesDelegate C_EX_ChangeVolumeAttributes = null;
        internal C_EX_SetLicenseDelegate C_EX_SetLicense = null;
        internal C_EX_GetLicenseDelegate C_EX_GetLicense = null;
        internal C_EX_GenerateActivationPasswordDelegate C_EX_GenerateActivationPassword = null;
        internal C_EX_LoadActivationKeyDelegate C_EX_LoadActivationKey = null;
        internal C_EX_SetActivationPasswordDelegate C_EX_SetActivationPassword = null;
        internal C_EX_TokenManageDelegate C_EX_TokenManage = null;
        internal C_EX_SlotManageDelegate C_EX_SlotManage = null;
        internal C_EX_WrapKeyDelegate C_EX_WrapKey = null;
        internal C_EX_UnwrapKeyDelegate C_EX_UnwrapKey = null;
        internal C_EX_CreateCSRDelegate C_EX_CreateCSR = null;
        internal C_EX_GetCertificateInfoTextDelegate C_EX_GetCertificateInfoText = null;
        internal C_EX_PKCS7SignDelegate C_EX_PKCS7Sign = null;
        internal C_EX_PKCS7VerifyInitDelegate C_EX_PKCS7VerifyInit = null;
        internal C_EX_PKCS7VerifyDelegate C_EX_PKCS7Verify = null;
        internal C_EX_PKCS7VerifyUpdateDelegate C_EX_PKCS7VerifyUpdate = null;
        internal C_EX_PKCS7VerifyFinalDelegate C_EX_PKCS7VerifyFinal = null;
        internal C_EX_FreeBufferDelegate C_EX_FreeBuffer = null;



        /// <summary>
        /// Initializes new instance of MockDelegates class
        /// </summary>
        /// <param name="libraryHandle">Handle to the PKCS#11 library</param>
        internal RutokenDelegates(IntPtr libraryHandle)
        {
            // Get delegates from the dynamically loaded shared PKCS#11 library
            if (libraryHandle != IntPtr.Zero)
            {
                this.C_EX_GetTokenInfoExtended = UnmanagedLibrary.GetFunctionDelegate<C_EX_GetTokenInfoExtendedDelegate>(libraryHandle, "C_EX_GetTokenInfoExtended");
                this.C_EX_InitToken = UnmanagedLibrary.GetFunctionDelegate<C_EX_InitTokenDelegate>(libraryHandle, "C_EX_InitToken");
                this.C_EX_UnblockUserPIN = UnmanagedLibrary.GetFunctionDelegate<C_EX_UnblockUserPINDelegate>(libraryHandle, "C_EX_UnblockUserPIN");
                this.C_EX_SetTokenName = UnmanagedLibrary.GetFunctionDelegate<C_EX_SetTokenNameDelegate>(libraryHandle, "C_EX_SetTokenName");
                this.C_EX_GetTokenName = UnmanagedLibrary.GetFunctionDelegate<C_EX_GetTokenNameDelegate>(libraryHandle, "C_EX_GetTokenName");
                this.C_EX_GetJournal = UnmanagedLibrary.GetFunctionDelegate<C_EX_GetJournalDelegate>(libraryHandle, "C_EX_GetJournal");
                this.C_EX_SignInvisibleInit = UnmanagedLibrary.GetFunctionDelegate<C_EX_SignInvisibleInitDelegate>(libraryHandle, "C_EX_SignInvisibleInit");
                this.C_EX_SignInvisible = UnmanagedLibrary.GetFunctionDelegate<C_EX_SignInvisibleDelegate>(libraryHandle, "C_EX_SignInvisible");
                this.C_EX_SetLocalPIN = UnmanagedLibrary.GetFunctionDelegate<C_EX_SetLocalPINDelegate>(libraryHandle, "C_EX_SetLocalPIN");
                this.C_EX_GetDriveSize = UnmanagedLibrary.GetFunctionDelegate<C_EX_GetDriveSizeDelegate>(libraryHandle, "C_EX_GetDriveSize");
                this.C_EX_FormatDrive = UnmanagedLibrary.GetFunctionDelegate<C_EX_FormatDriveDelegate>(libraryHandle, "C_EX_FormatDrive");
                this.C_EX_GetVolumesInfo = UnmanagedLibrary.GetFunctionDelegate<C_EX_GetVolumesInfoDelegate>(libraryHandle, "C_EX_GetVolumesInfo");
                this.C_EX_ChangeVolumeAttributes = UnmanagedLibrary.GetFunctionDelegate<C_EX_ChangeVolumeAttributesDelegate>(libraryHandle, "C_EX_ChangeVolumeAttributes");
                this.C_EX_SetLicense = UnmanagedLibrary.GetFunctionDelegate<C_EX_SetLicenseDelegate>(libraryHandle, "C_EX_SetLicense");
                this.C_EX_GetLicense = UnmanagedLibrary.GetFunctionDelegate<C_EX_GetLicenseDelegate>(libraryHandle, "C_EX_GetLicense");
                this.C_EX_GenerateActivationPassword = UnmanagedLibrary.GetFunctionDelegate<C_EX_GenerateActivationPasswordDelegate>(libraryHandle, "C_EX_GenerateActivationPassword");
                this.C_EX_LoadActivationKey = UnmanagedLibrary.GetFunctionDelegate<C_EX_LoadActivationKeyDelegate>(libraryHandle, "C_EX_LoadActivationKey");
                this.C_EX_SetActivationPassword = UnmanagedLibrary.GetFunctionDelegate<C_EX_SetActivationPasswordDelegate>(libraryHandle, "C_EX_SetActivationPassword");
                this.C_EX_TokenManage = UnmanagedLibrary.GetFunctionDelegate<C_EX_TokenManageDelegate>(libraryHandle, "C_EX_TokenManage");
                this.C_EX_SlotManage = UnmanagedLibrary.GetFunctionDelegate<C_EX_SlotManageDelegate>(libraryHandle, "C_EX_SlotManage");
                this.C_EX_WrapKey = UnmanagedLibrary.GetFunctionDelegate<C_EX_WrapKeyDelegate>(libraryHandle, "C_EX_WrapKey");
                this.C_EX_UnwrapKey = UnmanagedLibrary.GetFunctionDelegate<C_EX_UnwrapKeyDelegate>(libraryHandle, "C_EX_UnwrapKey");
                this.C_EX_CreateCSR = UnmanagedLibrary.GetFunctionDelegate<C_EX_CreateCSRDelegate>(libraryHandle, "C_EX_CreateCSR");
                this.C_EX_GetCertificateInfoText = UnmanagedLibrary.GetFunctionDelegate<C_EX_GetCertificateInfoTextDelegate>(libraryHandle, "C_EX_GetCertificateInfoText");
                this.C_EX_PKCS7Sign = UnmanagedLibrary.GetFunctionDelegate<C_EX_PKCS7SignDelegate>(libraryHandle, "C_EX_PKCS7Sign");
                this.C_EX_PKCS7VerifyInit = UnmanagedLibrary.GetFunctionDelegate<C_EX_PKCS7VerifyInitDelegate>(libraryHandle, "C_EX_PKCS7VerifyInit");
                this.C_EX_PKCS7Verify = UnmanagedLibrary.GetFunctionDelegate<C_EX_PKCS7VerifyDelegate>(libraryHandle, "C_EX_PKCS7Verify");
                this.C_EX_PKCS7VerifyUpdate = UnmanagedLibrary.GetFunctionDelegate<C_EX_PKCS7VerifyUpdateDelegate>(libraryHandle, "C_EX_PKCS7VerifyUpdate");
                this.C_EX_PKCS7VerifyFinal = UnmanagedLibrary.GetFunctionDelegate<C_EX_PKCS7VerifyFinalDelegate>(libraryHandle, "C_EX_PKCS7VerifyFinal");
                this.C_EX_FreeBuffer = UnmanagedLibrary.GetFunctionDelegate<C_EX_FreeBufferDelegate>(libraryHandle, "C_EX_FreeBuffer");
            }
            // Get delegates from the statically linked PKCS#11 library
            else
            {
                this.C_EX_GetTokenInfoExtended = RutokenNativeMethods.C_EX_GetTokenInfoExtended;
                this.C_EX_InitToken = RutokenNativeMethods.C_EX_InitToken;
                this.C_EX_UnblockUserPIN = RutokenNativeMethods.C_EX_UnblockUserPIN;
                this.C_EX_SetTokenName = RutokenNativeMethods.C_EX_SetTokenName;
                this.C_EX_GetTokenName = RutokenNativeMethods.C_EX_GetTokenName;
                this.C_EX_GetJournal = RutokenNativeMethods.C_EX_GetJournal;
                this.C_EX_SignInvisibleInit = RutokenNativeMethods.C_EX_SignInvisibleInit;
                this.C_EX_SignInvisible = RutokenNativeMethods.C_EX_SignInvisible;
                this.C_EX_SetLocalPIN = RutokenNativeMethods.C_EX_SetLocalPIN;
                this.C_EX_GetDriveSize = RutokenNativeMethods.C_EX_GetDriveSize;
                this.C_EX_FormatDrive = RutokenNativeMethods.C_EX_FormatDrive;
                this.C_EX_GetVolumesInfo = RutokenNativeMethods.C_EX_GetVolumesInfo;
                this.C_EX_ChangeVolumeAttributes = RutokenNativeMethods.C_EX_ChangeVolumeAttributes;
                this.C_EX_SetLicense = RutokenNativeMethods.C_EX_SetLicense;
                this.C_EX_GetLicense = RutokenNativeMethods.C_EX_GetLicense;
                this.C_EX_GenerateActivationPassword = RutokenNativeMethods.C_EX_GenerateActivationPassword;
                this.C_EX_LoadActivationKey = RutokenNativeMethods.C_EX_LoadActivationKey;
                this.C_EX_SetActivationPassword = RutokenNativeMethods.C_EX_SetActivationPassword;
                this.C_EX_TokenManage = RutokenNativeMethods.C_EX_TokenManage;
                this.C_EX_SlotManage = RutokenNativeMethods.C_EX_SlotManage;
                this.C_EX_WrapKey = RutokenNativeMethods.C_EX_WrapKey;
                this.C_EX_UnwrapKey = RutokenNativeMethods.C_EX_UnwrapKey;
                this.C_EX_CreateCSR = RutokenNativeMethods.C_EX_CreateCSR;
                this.C_EX_GetCertificateInfoText = RutokenNativeMethods.C_EX_GetCertificateInfoText;
                this.C_EX_PKCS7Sign = RutokenNativeMethods.C_EX_PKCS7Sign;
                this.C_EX_PKCS7VerifyInit = RutokenNativeMethods.C_EX_PKCS7VerifyInit;
                this.C_EX_PKCS7Verify = RutokenNativeMethods.C_EX_PKCS7Verify;
                this.C_EX_PKCS7VerifyUpdate = RutokenNativeMethods.C_EX_PKCS7VerifyUpdate;
                this.C_EX_PKCS7VerifyFinal = RutokenNativeMethods.C_EX_PKCS7VerifyFinal;
                this.C_EX_FreeBuffer = RutokenNativeMethods.C_EX_FreeBuffer;
            }
        }
    }
}