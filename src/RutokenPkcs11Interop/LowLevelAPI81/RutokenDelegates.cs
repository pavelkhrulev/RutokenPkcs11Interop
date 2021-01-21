using System;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.LowLevelAPI81;
using Net.Pkcs11Interop.Common;
using NativeULong = System.UInt64;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI81
{
    internal class RutokenDelegates
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_GetTokenInfoExtendedDelegate(NativeULong slotId, ref CK_TOKEN_INFO_EXTENDED info);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_InitTokenDelegate(NativeULong slotId, byte[] pin, NativeULong pinLen, ref CK_RUTOKEN_INIT_PARAM initInfo);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_UnblockUserPINDelegate(NativeULong session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_SetTokenNameDelegate(NativeULong session, byte[] label, NativeULong labelLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_GetTokenNameDelegate(NativeULong session, byte[] label, ref NativeULong labelLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_GetJournalDelegate(NativeULong slotId, byte[] journal, ref NativeULong journalLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_SignInvisibleInitDelegate(NativeULong session, ref CK_MECHANISM mechanism, NativeULong key);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_SignInvisibleDelegate(
            NativeULong session, byte[] data, NativeULong dataLen, byte[] signature, ref NativeULong signatureLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_SetLocalPINDelegate(NativeULong slotId, byte[] userPin, NativeULong userPinLen,
            byte[] newLocalPin, NativeULong localPinLen, NativeULong localPinId);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_GetDriveSizeDelegate(NativeULong slotId, ref NativeULong driveSize);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_FormatDriveDelegate(NativeULong slotId, NativeULong userType,
            byte[] pin, NativeULong pinLen,
            CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams, NativeULong initParamsCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_GetVolumesInfoDelegate(NativeULong slotId,
            [Out][MarshalAs(UnmanagedType.LPArray, SizeConst = 1)] CK_VOLUME_INFO_EXTENDED[] info, ref NativeULong infoCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_ChangeVolumeAttributesDelegate(NativeULong slotId, NativeULong userType,
            byte[] pin, NativeULong pinLen,
            NativeULong volumeId, NativeULong newAccessMode, bool permanent);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_SetLicenseDelegate(
            NativeULong session, NativeULong licenseNum, byte[] license, NativeULong licenseLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_GetLicenseDelegate(
            NativeULong session, NativeULong licenseNum, byte[] license, ref NativeULong licenseLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_GenerateActivationPasswordDelegate(NativeULong session, NativeULong passwordNumber,
            byte[] password, ref NativeULong passwordSize, NativeULong passwordCharacterSet);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_LoadActivationKeyDelegate(NativeULong session, byte[] key, NativeULong keySize);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_SetActivationPasswordDelegate(NativeULong slotId, byte[] password);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_TokenManageDelegate(NativeULong session, NativeULong mode, IntPtr value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_SlotManageDelegate(NativeULong slotId, NativeULong mode, IntPtr value);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_WrapKeyDelegate(NativeULong session, ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, NativeULong keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            NativeULong baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref NativeULong wrappedKeyLen, ref NativeULong key);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_UnwrapKeyDelegate(NativeULong session, ref CK_MECHANISM derivationMechanism,
            NativeULong baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, NativeULong wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, NativeULong keyAttributeCount,
            ref NativeULong key);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_CreateCSRDelegate(NativeULong session, NativeULong publicKey,
            IntPtr[] dn, NativeULong dnLength,
            out IntPtr csr, out NativeULong csrLength,
            NativeULong privateKey,
            IntPtr[] attributes, NativeULong attributesLength,
            IntPtr[] extensions, NativeULong extensionsLength);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_GetCertificateInfoTextDelegate(
            NativeULong session, NativeULong cert, out IntPtr info, out NativeULong infoLen);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_PKCS7SignDelegate(
            NativeULong session, byte[] data, NativeULong dataLen,
            NativeULong cert,
            out IntPtr envelope, out NativeULong encelopeLen,
            NativeULong privateKey,
            NativeULong[] certificates, NativeULong certificatesLen, NativeULong flags);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_PKCS7VerifyInitDelegate(
            NativeULong session, byte[] cms, NativeULong cmsSize,
            ref CK_VENDOR_X509_STORE store, NativeULong mode,
            NativeULong flags);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_PKCS7VerifyDelegate(
            NativeULong session,
            out IntPtr data, out NativeULong dataSize,
            out IntPtr signerCertificates, out NativeULong signerCertificatesCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_PKCS7VerifyUpdateDelegate(
            NativeULong session, byte[] data, NativeULong dataSize);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_PKCS7VerifyFinalDelegate(
            NativeULong session,
            out IntPtr signerCertificates, out NativeULong signerCertificatesCount);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate NativeULong C_EX_FreeBufferDelegate(IntPtr buffer);


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
